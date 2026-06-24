"""Auditoria proativa: a Nexus reaudita sozinha hosts autorizados, em
intervalos regulares, e só interrompe o criador quando algo MUDOU desde
a última checagem — diferente do fluxo reativo (scan_*), que só roda
quando pedido explicitamente.

Nenhum host é auditado automaticamente sem antes ter sido explicitamente
autorizado via add_authorized_asset — isso é decisão do criador, nunca
da Nexus por conta própria.
"""

from datetime import datetime, timedelta

from database.db import (
    add_authorized_asset,
    get_latest_finding,
    list_authorized_assets,
    record_finding,
    remove_authorized_asset,
    touch_asset_scan,
)
from tools import recon

_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


def is_due(last_scan_at: str | None, interval_hours: float, now: datetime | None = None) -> bool:
    """True se já passou tempo suficiente desde o último scan (ou nunca
    foi escaneado ainda)."""
    if last_scan_at is None:
        return True
    now = now or datetime.utcnow()
    last = datetime.strptime(last_scan_at, _TIMESTAMP_FORMAT)
    return now - last >= timedelta(hours=interval_hours)


def get_due_assets() -> list[str]:
    """Lista os hosts autorizados que já passaram do intervalo configurado
    e estão prontos para uma nova auditoria automática."""
    assets = list_authorized_assets()
    return [
        host
        for host, _added_at, interval_hours, last_scan_at in assets
        if is_due(last_scan_at, interval_hours)
    ]


def check_asset(host: str) -> tuple[bool, str]:
    """Roda uma auditoria leve (headers de segurança) em um host autorizado
    e compara com o último achado do mesmo tipo. Retorna (mudou?, resumo).
    Só grava um novo achado se algo realmente mudou — evita poluir o
    histórico com o mesmo resultado repetido a cada ciclo."""
    new_summary = recon.check_security_headers(host)
    previous = get_latest_finding(host, "security_headers")
    changed = previous is None or previous[0] != new_summary

    if changed:
        record_finding(host, "security_headers", new_summary)
    touch_asset_scan(host)
    return changed, new_summary


def authorize(host: str, interval_hours: float = 24) -> str:
    add_authorized_asset(host, interval_hours)
    return f"{host} autorizado para auditoria proativa a cada {interval_hours}h."


def revoke(host: str) -> str:
    remove_authorized_asset(host)
    return f"{host} removido da auditoria proativa."


def describe_monitored_assets() -> str:
    assets = list_authorized_assets()
    if not assets:
        return "Nenhum ativo autorizado para auditoria proativa ainda."
    lines = ["Ativos sob auditoria proativa:"]
    for host, added_at, interval_hours, last_scan_at in assets:
        last = last_scan_at or "nunca"
        lines.append(
            f"  {host}: a cada {interval_hours}h, autorizado em {added_at}, último scan: {last}"
        )
    return "\n".join(lines)
