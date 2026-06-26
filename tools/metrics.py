"""Métricas de evidência, derivadas da trilha de auditoria já existente.

Objetivo: transformar "eu acho que o Nexus funciona" em números
concretos que sobrevivem a uma pergunta de auditoria — quantas ações de
alto risco foram propostas vs aprovadas vs canceladas vs expiraram sem
resposta, em quanto tempo, e quantos IPs foram contidos. Isso é o que
permite, depois de meses de uso real, mostrar evidência em vez de
opinião — tanto para o criador decidir se a tese se sustenta, quanto
para qualquer conversa futura com terceiros interessados.

Não inventa nada: só agrega o que já está em pending_actions e events.
"""

from datetime import datetime

from database.db import get_events_since, get_pending_actions_since
from tools.firewall import list_blocked

_TIMESTAMP_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f")


def _parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    for fmt in _TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def _governance_breakdown(hours: float) -> dict:
    rows = get_pending_actions_since(hours)
    by_status = {"executada": 0, "cancelada": 0, "expirada": 0, "pending": 0}
    resolution_seconds = []
    for tool_name, status, created_at, resolved_at in rows:
        by_status[status] = by_status.get(status, 0) + 1
        if resolved_at:
            created = _parse_ts(created_at)
            resolved = _parse_ts(resolved_at)
            if created and resolved:
                resolution_seconds.append((resolved - created).total_seconds())

    total = sum(by_status.values())
    avg_resolution = sum(resolution_seconds) / len(resolution_seconds) if resolution_seconds else None
    return {
        "total_proposed": total,
        "by_status": by_status,
        "avg_resolution_seconds": avg_resolution,
    }


def _containment_breakdown(hours: float) -> dict:
    events = get_events_since(hours)
    blocked_ips = set()
    unblocked_ips = set()
    block_timestamps: dict[str, str] = {}
    detection_timestamps: dict[str, str] = {}
    latencies = []

    for event_type, source_ip, _detail, _action_taken, timestamp in events:
        if event_type == "firewall_block_confirmed" and source_ip:
            blocked_ips.add(source_ip)
            block_timestamps[source_ip] = timestamp
            if source_ip in detection_timestamps:
                detected = _parse_ts(detection_timestamps[source_ip])
                blocked = _parse_ts(timestamp)
                if detected and blocked:
                    latencies.append((blocked - detected).total_seconds())
        elif event_type == "firewall_unblock_confirmed" and source_ip:
            unblocked_ips.add(source_ip)
        elif event_type in ("ddos_severe", "ddos_suspect", "honeypot_hit") and source_ip:
            detection_timestamps.setdefault(source_ip, timestamp)

    avg_latency = sum(latencies) / len(latencies) if latencies else None
    return {
        "ips_blocked": len(blocked_ips),
        "ips_unblocked": len(unblocked_ips),
        "avg_detection_to_block_seconds": avg_latency,
        "latency_samples": len(latencies),
    }


def generate_metrics_report(hours: float = 24 * 7) -> str:
    """Relatório de evidência: governança de ações de alto risco e
    contenção real, derivado só da trilha de auditoria. Use um período
    maior que o resumo executivo (padrão: 7 dias) — métricas de evidência
    fazem mais sentido olhando uma janela maior que um dia."""
    gov = _governance_breakdown(hours)
    cont = _containment_breakdown(hours)

    lines = [f"═══ MÉTRICAS DE EVIDÊNCIA — últimos {hours:g}h ═══", ""]

    lines.append("Governança de ações de alto risco:")
    if gov["total_proposed"] == 0:
        lines.append("  Nenhuma ação de alto risco proposta neste período.")
    else:
        lines.append(f"  Propostas: {gov['total_proposed']}")
        for status, label in (
            ("executada", "Confirmadas e executadas"),
            ("cancelada", "Canceladas pelo criador"),
            ("expirada", "Expiraram sem resposta"),
            ("pending", "Ainda pendentes"),
        ):
            n = gov["by_status"].get(status, 0)
            if n:
                lines.append(f"    {label}: {n}")
        if gov["avg_resolution_seconds"] is not None:
            lines.append(f"  Tempo médio até resolução (aprovação/cancelamento/expiração): {gov['avg_resolution_seconds']:.0f}s")

    lines.append("")
    lines.append("Contenção de ameaças:")
    lines.append(f"  IPs isolados: {cont['ips_blocked']}")
    lines.append(f"  IPs desbloqueados: {cont['ips_unblocked']}")
    if cont["avg_detection_to_block_seconds"] is not None:
        lines.append(
            f"  Latência média detecção -> contenção: {cont['avg_detection_to_block_seconds']:.1f}s "
            f"(baseado em {cont['latency_samples']} amostra(s))"
        )
    else:
        lines.append("  Sem amostras suficientes para calcular latência de contenção neste período.")

    lines.append("")
    lines.append("Estado atual do firewall:")
    lines.append("  " + list_blocked().replace("\n", "\n  "))

    return "\n".join(lines)
