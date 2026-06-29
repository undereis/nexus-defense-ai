"""Resumo executivo: agrega a trilha de eventos de um período num único
relatório legível, em vez de o criador precisar vasculhar a auditoria
evento por evento para saber o que aconteceu enquanto não estava olhando.
"""

from collections import Counter

from database.db import get_events_since
from tools.firewall import list_blocked

_HIGHLIGHT_LABELS = {
    "ddos_severe": "Ataques DDoS auto-isolados",
    "ddos_suspect": "IPs suspeitos sinalizados",
    "honeypot_hit": "Capturas em honeypot",
    "honeypot_credential_captured": "Credenciais capturadas em honeypot",
    "firewall_drift": "Drift de firewall corrigido",
    "watchdog_healed": "Serviços reerguidos pelo watchdog",
    "proactive_audit_changed": "Mudanças detectadas em auditoria proativa",
    "social_engineering_content_generated": "Conteúdo de engenharia social gerado",
}


def generate_summary_report(hours: float = 24) -> str:
    events = get_events_since(hours)

    lines = [f"═══ RESUMO EXECUTIVO — últimas {hours:g}h ═══", ""]

    if not events:
        lines.append(f"Nenhum evento registrado nas últimas {hours:g}h.")
    else:
        counts = Counter(e[0] for e in events)
        lines.append(f"Total de eventos: {len(events)}")
        lines.append("")
        lines.append("Destaques:")
        any_highlight = False
        for event_type, label in _HIGHLIGHT_LABELS.items():
            n = counts.get(event_type, 0)
            if n:
                lines.append(f"  {label}: {n}")
                any_highlight = True
        if not any_highlight:
            lines.append("  Nenhum destaque relevante neste período.")
        lines.append("")
        lines.append("Todos os tipos de evento neste período:")
        for event_type, n in counts.most_common():
            lines.append(f"  {event_type}: {n}")

    lines.append("")
    lines.append("Estado atual do firewall:")
    lines.append("  " + list_blocked().replace("\n", "\n  "))

    # Painel de operação (Fase 8): assinantes, equipamentos, quedas abertas.
    # Import lazy para não acoplar o resumo executivo ao módulo de NOC.
    try:
        from tools.noc_report import noc_status_report

        lines.append("")
        lines.append(noc_status_report())
    except Exception:
        pass

    return "\n".join(lines)
