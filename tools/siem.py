"""Encaminhamento da auditoria para um SIEM (Frente I).

Manda os eventos da trilha de auditoria (tabela `events`) para um SIEM externo
de forma INCREMENTAL: um cursor (db.siem_state) guarda o id do último evento já
enviado, então cada ciclo só envia o que é novo. Suporta três destinos comuns:

  - elastic: bulk index (`POST <url>/_bulk`, ndjson, Authorization: ApiKey)
  - splunk:  HTTP Event Collector (`POST <hec_url>`, Authorization: Splunk <token>)
  - webhook: POST genérico de {"events": [...]} (Authorization: Bearer opcional)

Off por padrão (SIEM_MODE=off). Nunca levanta exceção nem trava o fluxo: falha
de rede/recusa do destino → cursor NÃO avança (reenvia no próximo ciclo). Não
loga evento de sucesso — isso criaria um loop de realimentação (cada envio
geraria um novo evento a enviar). Read-only sobre eventos já gravados.
"""

import json

import requests

from config import SIEM_BATCH, SIEM_INDEX, SIEM_MODE, SIEM_TOKEN, SIEM_URL
from database.db import (
    get_events_after_id,
    get_siem_cursor,
    log_event,
    set_siem_cursor,
)

_TIMEOUT = 15


def is_enabled() -> bool:
    return SIEM_MODE != "off" and bool(SIEM_URL)


def _event_to_doc(row) -> dict:
    eid, ts, etype, ip, detail, action = row
    return {
        "id": eid, "timestamp": ts, "event_type": etype,
        "source_ip": ip, "detail": detail, "action_taken": action, "source": "nexus",
    }


def _post_elastic(docs: list[dict]) -> bool:
    lines = []
    for d in docs:
        lines.append(json.dumps({"index": {"_index": SIEM_INDEX, "_id": d["id"]}}))
        lines.append(json.dumps(d))
    body = "\n".join(lines) + "\n"
    headers = {"Content-Type": "application/x-ndjson"}
    if SIEM_TOKEN:
        headers["Authorization"] = f"ApiKey {SIEM_TOKEN}"
    url = SIEM_URL.rstrip("/")
    if not url.endswith("/_bulk"):
        url += "/_bulk"
    resp = requests.post(url, data=body, headers=headers, timeout=_TIMEOUT)
    if resp.status_code >= 300:
        return False
    try:  # bulk responde 200 mesmo com erro por item → checar "errors"
        return not resp.json().get("errors", False)
    except ValueError:
        return True


def _post_splunk(docs: list[dict]) -> bool:
    body = "\n".join(json.dumps({"event": d, "sourcetype": "nexus"}) for d in docs)
    headers = {}
    if SIEM_TOKEN:
        headers["Authorization"] = f"Splunk {SIEM_TOKEN}"
    resp = requests.post(SIEM_URL, data=body, headers=headers, timeout=_TIMEOUT)
    if resp.status_code >= 300:
        return False
    try:
        return resp.json().get("code", 0) == 0  # HEC: code 0 = sucesso
    except ValueError:
        return True


def _post_webhook(docs: list[dict]) -> bool:
    headers = {"Content-Type": "application/json"}
    if SIEM_TOKEN:
        headers["Authorization"] = f"Bearer {SIEM_TOKEN}"
    resp = requests.post(SIEM_URL, json={"events": docs}, headers=headers, timeout=_TIMEOUT)
    return resp.status_code < 300


_SENDERS = {"elastic": _post_elastic, "splunk": _post_splunk, "webhook": _post_webhook}


def forward_new_events() -> str:
    """Envia os eventos ainda não encaminhados ao SIEM e avança o cursor só se
    o destino confirmou. Retorna um resumo (nunca levanta)."""
    if not is_enabled():
        return "SIEM desligado (SIEM_MODE=off ou SIEM_URL vazio)."
    sender = _SENDERS.get(SIEM_MODE)
    if sender is None:
        return f"SIEM_MODE inválido: {SIEM_MODE!r} (use elastic|splunk|webhook)."

    last = get_siem_cursor()
    rows = get_events_after_id(last, SIEM_BATCH)
    if not rows:
        return "SIEM: nada novo para enviar."

    docs = [_event_to_doc(r) for r in rows]
    try:
        ok = sender(docs)
    except (requests.RequestException, ValueError) as exc:
        log_event("siem_forward_error", None, f"mode={SIEM_MODE} error={exc!r}", action_taken="falhou")
        return f"SIEM: falha ao enviar ({exc}). Cursor mantido; tenta de novo no próximo ciclo."
    if not ok:
        log_event("siem_forward_error", None, f"mode={SIEM_MODE} destino recusou", action_taken="falhou")
        return "SIEM: o destino recusou o lote. Cursor mantido."

    new_cursor = rows[-1][0]
    set_siem_cursor(new_cursor)
    return f"SIEM: {len(docs)} evento(s) enviados ({SIEM_MODE}); cursor em {new_cursor}."


def describe_status() -> str:
    if SIEM_MODE == "off":
        return "SIEM: desligado (SIEM_MODE=off)."
    cursor = get_siem_cursor()
    pending = len(get_events_after_id(cursor, SIEM_BATCH))
    cfg = "configurado" if SIEM_URL else "⚠️ SEM SIEM_URL"
    return (f"SIEM: modo={SIEM_MODE} ({cfg}), cursor no evento {cursor}, "
            f"{pending} evento(s) na fila (lote {SIEM_BATCH}).")
