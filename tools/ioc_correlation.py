"""Correlação automática de IOCs: quem mostrou sinal de reconhecimento
hoje (varredura/sondagem) é bloqueado PREVENTIVAMENTE, antes de avançar
para um ataque de verdade — em vez de só reagir depois que o ataque já
está em andamento.

Duas fontes de sinal de reconhecimento, ambas já existentes no
projeto, sem inventar fonte nova:
1. honeypot_hits — por definição, qualquer conexão a um honeypot É
   reconhecimento (ninguém deveria saber que aquela porta existe).
2. Alertas de DPI (Suricata) cuja categoria/assinatura indica varredura
   ou sondagem (ex: "Attempted Information Leak", assinaturas com
   "SCAN" no nome) — sinal de reconhecimento contra serviços REAIS, não
   só a armadilha.

A escalada usa a mesma tabela threat_intel que já existe: um IP com
sinal de recon recebe múltiplas sinalizações de uma vez (peso maior que
uma sinalização isolada), o suficiente para cruzar o limiar de
"reincidente conhecido" (tools/threat_intel.is_repeat_offender) sem
precisar esperar um segundo ataque de verdade.
"""

from database.db import get_honeypot_services_for_ip, log_event, record_threat_flag
from tools import dpi
from tools.threat_intel import is_repeat_offender

# Quantas sinalizações de uma vez um sinal de recon gera — calibrado pra
# cruzar o threshold padrão de reputation_score (times_flagged*2 >= 10)
# com uma margem, sem precisar de múltiplos eventos de recon separados.
RECON_FLAG_WEIGHT = 5

_RECON_KEYWORDS = ("scan", "recon", "information leak", "probe", "sweep")


def _is_recon_alert(entry: dict) -> bool:
    alert = entry.get("alert", {})
    haystack = f"{alert.get('category', '')} {alert.get('signature', '')}".lower()
    return any(kw in haystack for kw in _RECON_KEYWORDS)


def get_recon_ips_from_dpi() -> set[str]:
    """IPs de origem de alertas de DPI cuja categoria/assinatura indica
    reconhecimento/varredura."""
    ips = set()
    for entry in dpi.get_alert_entries():
        if _is_recon_alert(entry):
            src_ip = entry.get("src_ip")
            if src_ip:
                ips.add(src_ip)
    return ips


def has_recon_signal(ip: str) -> bool:
    """True se o IP já mostrou sinal de reconhecimento — tocou honeypot
    OU gerou alerta de DPI categorizado como varredura/sondagem."""
    if get_honeypot_services_for_ip(ip):
        return True
    return ip in get_recon_ips_from_dpi()


def correlate_and_escalate(ip: str) -> str | None:
    """Se o IP mostra sinal de recon e ainda não é reincidente conhecido,
    sinaliza pesado na threat_intel (escalando para 'reincidente' sem
    esperar um segundo ataque). Retorna None se nada precisou ser feito
    (sem sinal de recon, ou já era reincidente), ou uma mensagem
    descrevendo a escalada feita."""
    if not has_recon_signal(ip):
        return None
    if is_repeat_offender(ip):
        return None  # já está no nível mais alto, nada a escalar

    for _ in range(RECON_FLAG_WEIGHT):
        record_threat_flag(ip)
    log_event(
        "ioc_recon_escalated", ip,
        "Sinal de reconhecimento detectado (honeypot e/ou DPI) — escalado para reincidente conhecido",
        action_taken="escalado",
    )
    return (
        f"{ip} mostrou sinal de reconhecimento (honeypot/DPI) e foi escalado para "
        "'reincidente conhecido' — qualquer atividade suspeita subsequente desse IP "
        "será tratada com prioridade máxima, sem esperar novo padrão se repetir."
    )


def describe_recon_watchlist() -> str:
    """Lista os IPs que mostraram sinal de recon via DPI nesta sessão
    (honeypot já tem sua própria listagem em list_honeypot_captures)."""
    ips = get_recon_ips_from_dpi()
    if not ips:
        return "Nenhum IP com sinal de reconhecimento via DPI registrado ainda."
    lines = [f"IPs com sinal de reconhecimento via DPI ({len(ips)}):"]
    for ip in sorted(ips):
        history_note = " — já é reincidente conhecido" if is_repeat_offender(ip) else ""
        lines.append(f"  {ip}{history_note}")
    return "\n".join(lines)
