"""Nexus Defense AI — ponto de entrada.

Roda localmente: um chat com o criador em primeiro plano e, em segundo
plano, um monitor de rede que aciona o agente automaticamente quando
detecta possíveis ataques (ex.: DDoS), permitindo que ele decida isolar
a origem do ataque.
"""

import threading
import time
from datetime import datetime

from agents.nexus_agent import _detector
from agents.runtime import ask_agent
from config import (
    ALERT_COOLDOWN_SECONDS,
    ALLOW_ACTIVE_EXPLOITATION,
    ALLOW_SOCIAL_ENGINEERING,
    ASSET_INVENTORY_SCAN_INTERVAL,
    ASSET_INVENTORY_SCAN_MODE,
    AUDIT_CHECKPOINT_INTERVAL,
    AUTO_ISOLATE_MULTIPLIER,
    CREATOR_NAME,
    DEVICE_MONITOR_INTERVAL,
    DNS_MONITOR_INTERVAL,
    DNS_PROBE_DOMAIN,
    DNS_SERVERS,
    HONEYPOT_ENABLED,
    HONEYPOT_SERVICES,
    MONITOR_POLL_INTERVAL,
    PROACTIVE_AUDIT_POLL_INTERVAL,
    RECONCILE_POLL_INTERVAL,
    REPORT_INTERVAL_HOURS,
    RISK_SWEEP_INTERVAL,
    SIEM_FORWARD_INTERVAL,
    SUBSCRIBER_BILLING_ENABLED,
    SUBSCRIBER_BLOCK_HOUR,
    THREAT_FEED_REFRESH_INTERVAL_HOURS,
    WATCHDOG_INTERVAL,
)
from core import control_plane as cp
from core import rbac
from database.db import (
    get_findings_for_host,
    init_db,
    log_event,
    record_threat_flag,
)
from tools import client_risk, firewall, honeypot
from tools.anomaly import record_current_sample
from tools import siem
from tools.billing import run_billing_cycle
from tools.device_monitor import check_all_devices
from tools.asset_inventory import scan_network as _inventory_scan
from tools.client_baseline import check_all_client_anomalies, record_all_client_samples
from tools.dns_monitor import (
    check_all_dns_health,
    has_problems as _dns_has_problems,
    register_dns_server,
)
from tools.audit import create_checkpoint
from tools.notify import send_notification
from tools.policy import classify_threats
from tools.proactive import check_asset, get_due_assets
from tools.reconcile import check_and_reconcile, describe
from tools.report import generate_summary_report
from tools.ioc_correlation import correlate_and_escalate
from tools.risk import sweep_expired
from tools.threat_feed_lists import check_ip_against_feeds, refresh_all_feeds
from tools.threat_intel import is_repeat_offender, record_confirmed_isolation
from tools.watchdog import check_and_heal

_last_alerted: dict[str, float] = {}
_feed_blocked_ips: set[str] = set()


def _announce(message: str) -> None:
    """Imprime um aviso vindo de uma thread em background sem embaralhar
    o que o criador estiver digitando na hora no prompt principal. `\\r`
    + limpar a linha (`\\033[K`) apaga o que já tinha sido desenhado ali
    antes de escrever o aviso por cima — sem isso, o aviso ficava
    intercalado caractere a caractere com o texto que a pessoa digitava,
    porque input() não sabe que outra thread moveu o cursor."""
    print(f"\r\033[K\n[Nexus] {message}\n> ", end="", flush=True)


def _due_for_alert(ips: list[str], now: float) -> list[str]:
    return [ip for ip in ips if now - _last_alerted.get(ip, 0) >= ALERT_COOLDOWN_SECONDS]


def monitor_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            _detector.sample()
            now = time.time()
            counts = _detector.snapshot_counts()
            record_current_sample(sum(counts.values()), len(counts))
            record_all_client_samples(counts)

            # Anomalia por cliente: detecta desvio específico de um cliente
            # antes que ele afete o volume global. O threshold é ajustado ao
            # risco de cada cliente (Fase 7, item 3): cliente arriscado é
            # monitorado de forma mais agressiva automaticamente.
            client_anomalies = check_all_client_anomalies(
                counts, z_threshold_fn=client_risk.adjusted_z_threshold
            )
            for ca in client_anomalies:
                log_event(
                    "client_anomaly_detected",
                    ca["client_id"],
                    f"z_score={ca['z_score']} current={ca['current']} mean={ca['mean']}",
                )
                _announce(
                    f"ANOMALIA POR CLIENTE: '{ca['client_id']}' com {ca['current']} conexões "
                    f"(z-score {ca['z_score']}, média histórica {ca['mean']})."
                )

            # Bloqueio proativo: qualquer IP ativo que já está numa lista
            # global de ameaça conhecida (Spamhaus/Feodo/ET) é isolado na
            # hora, sem esperar threshold de volume — o "quem já é
            # malicioso em qualquer lugar" não precisa atacar a Xfiber
            # primeiro pra ser bloqueado aqui.
            for ip in counts:
                if ip in _feed_blocked_ips:
                    continue
                feed_matches = check_ip_against_feeds(ip)
                if feed_matches:
                    reason = f"IP em feed(s) de threat intel conhecido: {', '.join(feed_matches)}"
                    log_event("threat_feed_match", ip, reason)
                    result = firewall.block_ip(ip, reason)
                    record_confirmed_isolation(ip, reason)
                    _feed_blocked_ips.add(ip)
                    _announce(f"BLOQUEIO PROATIVO (threat feed): {result} ({reason})")
                    send_notification("Nexus: IP isolado proativamente (threat feed)", f"{ip} — {reason}\n{result}")

            severe, moderate = classify_threats(
                counts, _detector.threshold, AUTO_ISOLATE_MULTIPLIER
            )

            # Correlação de IOC: qualquer IP moderado que já mostrou sinal
            # de reconhecimento (honeypot ou DPI categorizado como
            # varredura) é escalado ANTES de decidir severo/moderado —
            # "quem varreu hoje, tratado com prioridade máxima hoje",
            # sem esperar um segundo padrão de ataque se repetir.
            for ip in moderate:
                escalation_note = correlate_and_escalate(ip)
                if escalation_note:
                    log_event("ioc_correlation_triggered", ip, escalation_note, action_taken="escalado")

            # Memória institucional: um IP moderado que já é reincidente
            # conhecido (atacou/foi isolado antes, OU acabou de ser
            # escalado por sinal de recon acima) não precisa repetir todo
            # o processo de novo — escala direto para o caminho rápido.
            escalated = [ip for ip in moderate if is_repeat_offender(ip)]
            if escalated:
                severe = severe + escalated
                moderate = [ip for ip in moderate if ip not in escalated]

            due_severe = _due_for_alert(severe, now)
            due_moderate = _due_for_alert(moderate, now)
            for ip in due_severe + due_moderate:
                _last_alerted[ip] = now

            # Caminho rápido: ameaça muito acima do threshold (ou reincidente
            # conhecido) é isolada na hora, sem esperar round-trip de LLM.
            for ip in due_severe:
                reason = (
                    "Auto-isolado: reincidente conhecido"
                    if ip in escalated
                    else f"Auto-isolado: conexões {counts[ip]}x acima do normal"
                )
                log_event("ddos_severe", ip, reason)
                record_threat_flag(ip)
                result = firewall.block_ip(ip, reason)
                record_confirmed_isolation(ip, reason)
                _announce(f"AÇÃO AUTOMÁTICA: {result} ({reason})")
                send_notification("Nexus: IP isolado automaticamente", f"{ip} — {reason}\n{result}")

                prior_findings = get_findings_for_host(ip, limit=3)
                findings_note = (
                    f" Já existem {len(prior_findings)} auditoria(s) de segurança prévia(s) "
                    f"registrada(s) para esse IP — use correlate_threat para checar."
                    if prior_findings
                    else ""
                )
                ask_agent(
                    f"AVISO: acabei de isolar automaticamente o IP {ip} ({reason}), "
                    "pois estava muito acima do limite configurado." + findings_note +
                    " Confirme que está registrado e me explique resumidamente o que foi feito.",
                    principal=rbac.SERVICE_MONITOR_PRINCIPAL,
                )

            # Caminho normal: ameaça moderada continua sendo avaliada pelo agente.
            if due_moderate:
                for ip in due_moderate:
                    log_event("ddos_suspect", ip, "Limite de conexões excedido na janela de monitoramento")
                    record_threat_flag(ip)
                alert = (
                    "ALERTA AUTOMÁTICO DO MONITOR DE REDE: os seguintes IPs excederam o "
                    f"limite de conexões na janela de monitoramento e são suspeitos de DDoS: "
                    f"{', '.join(due_moderate)}. Avalie e decida se deve isolá-los, explicando o motivo."
                )
                _announce("Anomalia detectada, analisando...")
                reply = ask_agent(alert, principal=rbac.SERVICE_MONITOR_PRINCIPAL)
                _announce(reply)
        except Exception as exc:
            log_event("monitor_error", None, str(exc))
        stop_event.wait(MONITOR_POLL_INTERVAL)


def proactive_audit_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            for host in get_due_assets():
                changed, summary = check_asset(host)
                if changed:
                    _announce(f"Auditoria proativa detectou mudança em {host}, analisando...")
                    log_event("proactive_audit_changed", host, "Achado diferente do último scan")
                    send_notification(
                        "Nexus: mudança detectada em auditoria proativa",
                        f"Host: {host}\n\n{summary[:500]}",
                    )
                    reply = ask_agent(
                        f"AUDITORIA PROATIVA: reauditei {host} (monitoramento automático que você "
                        f"autorizou) e o resultado mudou desde a última vez. Novo resultado:\n\n"
                        f"{summary}\n\nMe avise resumidamente o que mudou e se é preocupante.",
                        principal=rbac.SERVICE_PROACTIVE_AUDIT_PRINCIPAL,
                    )
                    _announce(reply)
                else:
                    log_event("proactive_audit_unchanged", host, "Sem mudanças desde o último scan")
        except Exception as exc:
            log_event("proactive_audit_error", None, str(exc))
        stop_event.wait(PROACTIVE_AUDIT_POLL_INTERVAL)


def reconcile_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            result = check_and_reconcile(auto_reapply=True)
            if result.has_drift:
                description = describe(result)
                log_event("firewall_drift", None, description)
                _announce(description)
                send_notification("Nexus: drift detectado no firewall", description)
                ask_agent(
                    "ALERTA: detectei e corrigi divergência entre o que eu achava que estava "
                    f"bloqueado e o estado real do firewall.\n\n{description}\n\n"
                    "Resuma o que aconteceu e por que isso é importante.",
                    principal=rbac.SERVICE_RECONCILE_PRINCIPAL,
                )
        except Exception as exc:
            log_event("reconcile_error", None, str(exc))
        stop_event.wait(RECONCILE_POLL_INTERVAL)


def audit_checkpoint_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            with cp.principal_context(rbac.SERVICE_WATCHDOG_PRINCIPAL):
                req = cp.make_request("audit.checkpoint", target="audit_checkpoint")
                cp.request_action(req, executor=create_checkpoint, tool_name="cp_audit_checkpoint")
        except Exception as exc:
            log_event("audit_checkpoint_error", None, str(exc))
        stop_event.wait(AUDIT_CHECKPOINT_INTERVAL)


def watchdog_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            captured: dict = {}

            def _do():
                # Captura a lista REAL (não a versão em string que o Control
                # Plane devolve em .output) para a checagem de truthiness
                # abaixo continuar correta mesmo com lista vazia.
                captured["healed"] = check_and_heal()
                return captured["healed"]

            with cp.principal_context(rbac.SERVICE_WATCHDOG_PRINCIPAL):
                req = cp.make_request("watchdog.check_health", target="watchdog")
                cp.request_action(req, executor=_do, tool_name="cp_watchdog_check")
            if captured.get("healed"):
                _announce(f"Watchdog reergueu: {', '.join(captured['healed'])}")
        except Exception as exc:
            log_event("watchdog_error", None, str(exc))
        stop_event.wait(WATCHDOG_INTERVAL)


def threat_feed_refresh_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            result = refresh_all_feeds()
            log_event("threat_feed_refresh", None, result, action_taken="atualizado")
        except Exception as exc:
            log_event("threat_feed_refresh_error", None, str(exc))
        stop_event.wait(THREAT_FEED_REFRESH_INTERVAL_HOURS * 3600)


def asset_inventory_loop(stop_event: threading.Event):
    """Varredura periódica dos blocos IP próprios para detectar novos devices
    ou mudanças de configuração. Só roda se ASSET_INVENTORY_SCAN_INTERVAL > 0."""
    if ASSET_INVENTORY_SCAN_INTERVAL <= 0:
        return
    while not stop_event.is_set():
        try:
            result = _inventory_scan(mode=ASSET_INVENTORY_SCAN_MODE)
            if "NOVO" in result or "MUDANÇA" in result:
                _announce(f"Inventário de ativos: {result}")
                send_notification("Nexus: mudança no inventário de ativos", result)
                log_event("asset_inventory_changes", None, result[:500], action_taken="notificado")
            else:
                log_event("asset_inventory_ok", None, result[:200])
        except Exception as exc:
            log_event("asset_inventory_error", None, str(exc))
        stop_event.wait(ASSET_INVENTORY_SCAN_INTERVAL)


def dns_monitor_loop(stop_event: threading.Event):
    """Health check periódico dos DNS servers (resposta, portas, certificado).
    Só roda se DNS_MONITOR_INTERVAL > 0. Cadastra DNS_SERVERS no primeiro ciclo."""
    if DNS_MONITOR_INTERVAL <= 0:
        return
    for ip in (s.strip() for s in DNS_SERVERS.split(",")):
        if ip:
            try:
                register_dns_server(ip, description="auto-cadastrado via DNS_SERVERS")
            except Exception as exc:
                log_event("dns_register_error", ip, str(exc))
    while not stop_event.is_set():
        try:
            report = check_all_dns_health(DNS_PROBE_DOMAIN)
            if _dns_has_problems(report):
                _announce(f"DNS: problema(s) detectado(s)\n{report}")
                send_notification("Nexus: problema em DNS server", report)
                log_event("dns_health_problem", None, report[:500], action_taken="notificado")
            else:
                log_event("dns_health_ok", None, report[:200])
        except Exception as exc:
            log_event("dns_health_error", None, str(exc))
        stop_event.wait(DNS_MONITOR_INTERVAL)


def risk_sweep_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            captured: dict = {}

            def _do():
                # Idem watchdog_loop: preserva a lista real para o `if`
                # abaixo (uma string "[]" seria truthy por engano).
                captured["expired"] = sweep_expired()
                return captured["expired"]

            with cp.principal_context(rbac.SERVICE_WATCHDOG_PRINCIPAL):
                req = cp.make_request("risk.sweep_expired", target="risk_sweep")
                cp.request_action(req, executor=_do, tool_name="cp_risk_sweep")
            if captured.get("expired"):
                _announce(f"Ação(ões) pendente(s) expirada(s) sem confirmação: {captured['expired']}")
        except Exception as exc:
            log_event("risk_sweep_error", None, str(exc))
        stop_event.wait(RISK_SWEEP_INTERVAL)


def report_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            with cp.principal_context(rbac.SERVICE_WATCHDOG_PRINCIPAL):
                req = cp.make_request(
                    "report.generate", target="report", params={"hours": REPORT_INTERVAL_HOURS}
                )
                result = cp.request_action(
                    req, executor=generate_summary_report, tool_name="cp_report_generate"
                )
            if result.status is cp.ActionStatus.EXECUTED:
                send_notification(f"Nexus: resumo executivo ({REPORT_INTERVAL_HOURS:g}h)", result.output)
                log_event("summary_report_sent", None, f"hours={REPORT_INTERVAL_HOURS}", action_taken="enviado")
        except Exception as exc:
            log_event("report_error", None, str(exc))
        stop_event.wait(REPORT_INTERVAL_HOURS * 3600)


# A cada quantos segundos o loop de cobrança verifica se já é a hora agendada
# de rodar o ciclo diário. A guarda por data garante que roda no máximo uma vez
# por dia, mesmo checando de 5 em 5 minutos.
_BILLING_POLL_INTERVAL = 300


def subscriber_billing_loop(stop_event: threading.Event):
    """Roda o ciclo de cobrança (bloqueio de inadimplentes / reativação) uma
    vez por dia, na hora SUBSCRIBER_BLOCK_HOUR. Só ativo se
    SUBSCRIBER_BILLING_ENABLED. O ciclo em si tem cap de segurança (não
    bloqueia lote anormal) — ver tools/billing.run_billing_cycle."""
    if not SUBSCRIBER_BILLING_ENABLED:
        return
    last_run_date = None
    while not stop_event.is_set():
        try:
            now = datetime.now()
            if now.hour == SUBSCRIBER_BLOCK_HOUR and now.date() != last_run_date:
                last_run_date = now.date()
                _announce("Rodando ciclo de cobrança (bloqueio de inadimplentes)...")
                summary = run_billing_cycle()
                log_event("billing_cycle_loop", None, summary[:300], action_taken="executado")
                _announce(summary)
        except Exception as exc:
            log_event("billing_loop_error", None, str(exc))
        stop_event.wait(_BILLING_POLL_INTERVAL)


def device_monitor_loop(stop_event: threading.Event):
    """Ping periódico nos equipamentos cadastrados (Microkit/OLT/switch),
    abrindo/baixando chamados de queda e notificando transições. Só roda se
    DEVICE_MONITOR_INTERVAL > 0."""
    if DEVICE_MONITOR_INTERVAL <= 0:
        return
    while not stop_event.is_set():
        try:
            transitions = check_all_devices()
            if transitions:
                _announce("Monitor de equipamentos: " + "; ".join(transitions))
        except Exception as exc:
            log_event("device_monitor_error", None, str(exc))
        stop_event.wait(DEVICE_MONITOR_INTERVAL)


def siem_loop(stop_event: threading.Event):
    """Encaminha os eventos novos da auditoria ao SIEM externo, incremental.
    Só roda se SIEM_MODE != off e SIEM_URL configurado. Não loga o resultado
    de rotina (evitaria realimentação: cada log vira evento a encaminhar)."""
    if not siem.is_enabled():
        return
    while not stop_event.is_set():
        try:
            siem.forward_new_events()
        except Exception as exc:
            log_event("siem_loop_error", None, str(exc))
        stop_event.wait(SIEM_FORWARD_INTERVAL)


def main():
    init_db()
    print("=== Nexus Defense AI ===")
    print(f"Online. Olá, {CREATOR_NAME}. Estou monitorando a rede em segundo plano.")
    print(
        f"Exploração ativa (Metasploit/Hydra/SQLMap): "
        f"{'LIGADA' if ALLOW_ACTIVE_EXPLOITATION else 'desligada'} | "
        f"Engenharia social: {'LIGADA' if ALLOW_SOCIAL_ENGINEERING else 'desligada'} | "
        f"Honeypot: {'LIGADO (' + HONEYPOT_SERVICES + ')' if HONEYPOT_ENABLED else 'desligado'}"
    )
    print(
        "Lembrete: mudanças no .env só valem depois de reiniciar este processo "
        "('sair' + rodar de novo).\n"
    )
    print("Digite 'sair' para encerrar.\n")

    stop_event = threading.Event()
    monitor_thread = threading.Thread(target=monitor_loop, args=(stop_event,), daemon=True)
    monitor_thread.start()
    proactive_thread = threading.Thread(
        target=proactive_audit_loop, args=(stop_event,), daemon=True
    )
    proactive_thread.start()
    reconcile_thread = threading.Thread(target=reconcile_loop, args=(stop_event,), daemon=True)
    reconcile_thread.start()
    checkpoint_thread = threading.Thread(
        target=audit_checkpoint_loop, args=(stop_event,), daemon=True
    )
    checkpoint_thread.start()
    if HONEYPOT_ENABLED:
        for entry in HONEYPOT_SERVICES.split(","):
            service, _, port_str = entry.strip().partition(":")
            print(honeypot.start(service, int(port_str) if port_str else 0))
    watchdog_thread = threading.Thread(target=watchdog_loop, args=(stop_event,), daemon=True)
    watchdog_thread.start()
    report_thread = threading.Thread(target=report_loop, args=(stop_event,), daemon=True)
    report_thread.start()
    risk_sweep_thread = threading.Thread(target=risk_sweep_loop, args=(stop_event,), daemon=True)
    risk_sweep_thread.start()
    threat_feed_thread = threading.Thread(target=threat_feed_refresh_loop, args=(stop_event,), daemon=True)
    threat_feed_thread.start()
    asset_inventory_thread = threading.Thread(
        target=asset_inventory_loop, args=(stop_event,), daemon=True
    )
    asset_inventory_thread.start()
    dns_monitor_thread = threading.Thread(
        target=dns_monitor_loop, args=(stop_event,), daemon=True
    )
    dns_monitor_thread.start()
    billing_thread = threading.Thread(
        target=subscriber_billing_loop, args=(stop_event,), daemon=True
    )
    billing_thread.start()
    device_monitor_thread = threading.Thread(
        target=device_monitor_loop, args=(stop_event,), daemon=True
    )
    device_monitor_thread.start()
    siem_thread = threading.Thread(target=siem_loop, args=(stop_event,), daemon=True)
    siem_thread.start()

    try:
        while True:
            user_text = input("> ").strip()
            if not user_text:
                continue
            if user_text.lower() in {"sair", "exit", "quit"}:
                break
            try:
                reply = ask_agent(user_text)
                print(f"\n[Nexus] {reply}\n")
            except Exception as exc:
                log_event("chat_error", None, str(exc))
                print(f"\n[Nexus] Tive um erro interno processando isso: {exc}\n")
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        stop_event.set()
        if honeypot.is_running():
            honeypot.stop()
        print("\nNexus Defense AI encerrada.")


if __name__ == "__main__":
    main()
