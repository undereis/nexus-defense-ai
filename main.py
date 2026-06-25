"""Nexus Defense AI — ponto de entrada.

Roda localmente: um chat com o criador em primeiro plano e, em segundo
plano, um monitor de rede que aciona o agente automaticamente quando
detecta possíveis ataques (ex.: DDoS), permitindo que ele decida isolar
a origem do ataque.
"""

import threading
import time

from agents.nexus_agent import _detector
from agents.runtime import ask_agent
from config import (
    ALERT_COOLDOWN_SECONDS,
    ALLOW_ACTIVE_EXPLOITATION,
    ALLOW_SOCIAL_ENGINEERING,
    AUDIT_CHECKPOINT_INTERVAL,
    AUTO_ISOLATE_MULTIPLIER,
    CREATOR_NAME,
    MONITOR_POLL_INTERVAL,
    PROACTIVE_AUDIT_POLL_INTERVAL,
    RECONCILE_POLL_INTERVAL,
)
from database.db import (
    get_findings_for_host,
    init_db,
    log_event,
    record_threat_flag,
    record_threat_isolation,
)
from tools import firewall
from tools.audit import create_checkpoint
from tools.notify import send_notification
from tools.policy import classify_threats
from tools.proactive import check_asset, get_due_assets
from tools.reconcile import check_and_reconcile, describe
from tools.threat_intel import is_repeat_offender

_last_alerted: dict[str, float] = {}


def _due_for_alert(ips: list[str], now: float) -> list[str]:
    return [ip for ip in ips if now - _last_alerted.get(ip, 0) >= ALERT_COOLDOWN_SECONDS]


def monitor_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            _detector.sample()
            now = time.time()
            counts = _detector.snapshot_counts()
            severe, moderate = classify_threats(
                counts, _detector.threshold, AUTO_ISOLATE_MULTIPLIER
            )

            # Memória institucional: um IP moderado que já é reincidente
            # conhecido (atacou/foi isolado antes) não precisa repetir todo
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
                    f"Auto-isolado: reincidente conhecido"
                    if ip in escalated
                    else f"Auto-isolado: conexões {counts[ip]}x acima do normal"
                )
                log_event("ddos_severe", ip, reason)
                record_threat_flag(ip)
                result = firewall.block_ip(ip, reason)
                record_threat_isolation(ip)
                print(f"\n[Nexus] AÇÃO AUTOMÁTICA: {result} ({reason})\n> ", end="", flush=True)
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
                    " Confirme que está registrado e me explique resumidamente o que foi feito."
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
                print(f"\n[Nexus] Anomalia detectada, analisando...")
                reply = ask_agent(alert)
                print(f"\n[Nexus] {reply}\n> ", end="", flush=True)
        except Exception as exc:
            log_event("monitor_error", None, str(exc))
        stop_event.wait(MONITOR_POLL_INTERVAL)


def proactive_audit_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            for host in get_due_assets():
                changed, summary = check_asset(host)
                if changed:
                    print(f"\n[Nexus] Auditoria proativa detectou mudança em {host}, analisando...")
                    log_event("proactive_audit_changed", host, "Achado diferente do último scan")
                    send_notification(
                        "Nexus: mudança detectada em auditoria proativa",
                        f"Host: {host}\n\n{summary[:500]}",
                    )
                    reply = ask_agent(
                        f"AUDITORIA PROATIVA: reauditei {host} (monitoramento automático que você "
                        f"autorizou) e o resultado mudou desde a última vez. Novo resultado:\n\n"
                        f"{summary}\n\nMe avise resumidamente o que mudou e se é preocupante."
                    )
                    print(f"\n[Nexus] {reply}\n> ", end="", flush=True)
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
                print(f"\n[Nexus] {description}\n> ", end="", flush=True)
                send_notification("Nexus: drift detectado no firewall", description)
                ask_agent(
                    "ALERTA: detectei e corrigi divergência entre o que eu achava que estava "
                    f"bloqueado e o estado real do firewall.\n\n{description}\n\n"
                    "Resuma o que aconteceu e por que isso é importante."
                )
        except Exception as exc:
            log_event("reconcile_error", None, str(exc))
        stop_event.wait(RECONCILE_POLL_INTERVAL)


def audit_checkpoint_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            create_checkpoint()
        except Exception as exc:
            log_event("audit_checkpoint_error", None, str(exc))
        stop_event.wait(AUDIT_CHECKPOINT_INTERVAL)


def main():
    init_db()
    print("=== Nexus Defense AI ===")
    print(f"Online. Olá, {CREATOR_NAME}. Estou monitorando a rede em segundo plano.")
    print(
        f"Exploração ativa (Metasploit/Hydra/SQLMap): "
        f"{'LIGADA' if ALLOW_ACTIVE_EXPLOITATION else 'desligada'} | "
        f"Engenharia social: {'LIGADA' if ALLOW_SOCIAL_ENGINEERING else 'desligada'}"
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
        print("\nNexus Defense AI encerrada.")


if __name__ == "__main__":
    main()
