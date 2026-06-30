"""Fachada de dados/ações para clientes externos (GUI Delphi, etc).

Camada fina, JSON-serializável, sobre o que já existe (Fase 8 + auditoria):
transforma as tuplas do banco em dicts estáveis e expõe as ações operacionais
comuns. É o contrato que os endpoints REST de api/server.py (`/api/*`) servem —
mantê-lo aqui (e não inline no FastAPI) deixa o formato testável sem subir o
servidor e desacopla a API HTTP da forma dos dados.

Read-only nas consultas; as ações reaproveitam tools/billing e
tools/device_monitor (mesma guarda/auditoria do resto do sistema).
"""

from core import control_plane as cp
from database.db import (
    get_events_since,
    list_device_outages,
    list_monitored_devices,
    list_subscribers,
)
from tools import billing, device_monitor, selftest


# ---------- consultas (JSON-serializáveis) ----------

def subscribers() -> list[dict]:
    return [
        {"id": s[0], "name": s[1], "ip": s[2], "device_host": s[3], "interface": s[4],
         "status": s[5], "invoice_status": s[6], "days_overdue": s[7]}
        for s in list_subscribers()
    ]


def devices() -> list[dict]:
    return [
        {"id": d[0], "name": d[1], "ip": d[2], "model": d[3], "location": d[4],
         "type": d[5], "enabled": bool(d[6]), "status": d[7], "last_change": d[8]}
        for d in list_monitored_devices()
    ]


def outages(status: str = "aberto") -> list[dict]:
    return [
        {"device_id": o[0], "ip": o[1], "name": o[2], "reason": o[3],
         "status": o[4], "opened_at": o[5], "resolved_at": o[6]}
        for o in list_device_outages(status or None, limit=100)
    ]


def events(hours: float = 24) -> list[dict]:
    rows = get_events_since(hours)
    return [
        {"type": e[0], "ip": e[1] or "", "detail": e[2] or "", "action": e[3] or "", "time": e[4]}
        for e in rows[-200:]
    ]


def health() -> dict:
    return {"report": selftest.run_selftest()}


# ---------- ações (token-gated nos endpoints; agora via Control Plane) ----------
# Importante: estas ações vêm da API REST / cliente Tauri. Roteá-las pelo Control
# Plane fecha o bypass pela API (a governança não vale só para o agente): toda
# ação passa por política + inventário + modo operacional + auditoria. Em modo
# lab/replay, vira dry-run (não toca o estado real). O contrato {"message": ...}
# é preservado; um campo "decision" é ADICIONADO (aditivo, clientes ignoram).

def block_subscriber(subscriber_id: str, reason: str = "bloqueio via API",
                     actor: str = "", role: str = "") -> dict:
    req = cp.make_request(
        "block_subscriber", target=subscriber_id, actor=actor, role=role,
        params={"subscriber_id": subscriber_id, "reason": reason},
    )
    res = cp.request_action(req, executor=billing.block_subscriber_by_id, tool_name="cp_block_subscriber")
    return {"message": res.output, "decision": res.decision.decision.value, "status": res.status.value}


def unblock_subscriber(subscriber_id: str, reason: str = "desbloqueio via API",
                       actor: str = "", role: str = "") -> dict:
    req = cp.make_request(
        "unblock_subscriber", target=subscriber_id, actor=actor, role=role,
        params={"subscriber_id": subscriber_id, "reason": reason},
    )
    res = cp.request_action(req, executor=billing.unblock_subscriber_by_id, tool_name="cp_unblock_subscriber")
    return {"message": res.output, "decision": res.decision.decision.value, "status": res.status.value}


def run_billing(dry_run: bool = True) -> dict:
    return {"message": billing.run_billing_cycle(dry_run=dry_run)}


def check_devices() -> dict:
    return {"transitions": device_monitor.check_all_devices()}
