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

CP-SD Fase 6H: o envio real (sender + avanço de cursor) passa por
`cp.request_action` (action_type "siem.forward_events", changes_state=True) —
RBAC nega sem tocar rede; lab/replay vira DRY_RUN_ONLY (nunca chama
requests.post). `is_enabled()`/modo inválido/"nada novo para enviar"
continuam resolvidos ANTES do Control Plane (não criam ActionRequest à toa).

CP-SD Fase 6J/6K: quando a decisão é DENY/DRY_RUN_ONLY, nada é enviado e o
cursor não avança — o Control Plane reauditaria a MESMA decisão a cada
`SIEM_FORWARD_INTERVAL` (60s padrão), gravando um `control_plane_decision`
novo por ciclo pra sempre (achado 6I/6J: cresce sem nunca sair da fila e
pode enfileirar eventos reais atrás do próprio ruído). Um cooldown de
reavaliação (`siem_state.last_blocked_*`, `SIEM_REAUDIT_COOLDOWN_SECONDS`)
pula a reauditoria enquanto a MESMA combinação action_type/decisão/modo/
actor/role continuar bloqueada — sem tocar `events`/hash chain, sem avançar
cursor, sem descartar o lote real que segue preso até a causa ser corrigida.
"""

import json
from contextlib import nullcontext
from datetime import datetime, timezone

import requests

from config import (
    SIEM_BATCH,
    SIEM_INDEX,
    SIEM_MODE,
    SIEM_REAUDIT_COOLDOWN_SECONDS,
    SIEM_TOKEN,
    SIEM_URL,
)
from core import control_plane as cp
from core import operating_mode, rbac
from database.db import (
    clear_siem_blocked_state,
    get_events_after_id,
    get_siem_blocked_state,
    get_siem_cursor,
    log_event,
    set_siem_blocked_state,
    set_siem_cursor,
)

_TIMEOUT = 15
_BLOCKED_STATUSES = (cp.ActionStatus.DENIED.value, cp.ActionStatus.DRY_RUN.value)


def is_enabled() -> bool:
    return SIEM_MODE != "off" and bool(SIEM_URL)


def _siem_principal_context():
    """Identidade a usar na chamada ao Control Plane do envio real.

    NUNCA sobrescreve um Principal real já propagado no contexto (chat/API/
    Slack/Telegram) — só assume SERVICE_SIEM_PRINCIPAL quando NINGUÉM setou
    Principal (caso do `siem_loop` automático, que não tem identidade
    própria). Mesma lição da CP-SD Fase 6D (tools/billing.py): sobrescrever
    incondicionalmente seria elevação de privilégio — um chamador sem
    `siem.forward_events` (ex.: readonly via chat, através da tool do agente
    `siem_forward_now`) poderia "virar" service:siem só por invocar a tool."""
    if cp.get_current_principal() is not None:
        return nullcontext()
    return cp.principal_context(rbac.SERVICE_SIEM_PRINCIPAL)


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


def _effective_principal():
    """Mesma regra da `_siem_principal_context()`: Principal real se já
    houver um no ContextVar, senão SERVICE_SIEM_PRINCIPAL — usada aqui só
    para LER a identidade que o Control Plane vai resolver (comparação de
    cooldown), sem entrar no contexto."""
    return cp.get_current_principal() or rbac.SERVICE_SIEM_PRINCIPAL


def _seconds_until_cooldown_expires(blocked_at: str) -> float:
    ts = datetime.strptime(blocked_at, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    elapsed = (datetime.now(timezone.utc) - ts).total_seconds()
    return SIEM_REAUDIT_COOLDOWN_SECONDS - elapsed


def _blocked_state_still_applies(blocked: dict, actor: str, role: str, op_mode: str) -> bool:
    """True se o bloqueio registrado é a MESMA situação de agora (mesma ação,
    mesma decisão DENY/DRY_RUN, mesmo modo operacional, mesmo actor/role) e o
    cooldown ainda não expirou — reavaliar de novo seria redundante."""
    if blocked["action_type"] != "siem.forward_events":
        return False
    if blocked["decision"] not in _BLOCKED_STATUSES:
        return False
    if blocked["mode"] != op_mode or blocked["actor"] != actor or blocked["role"] != role:
        return False
    return _seconds_until_cooldown_expires(blocked["blocked_at"]) > 0


def forward_new_events() -> str:
    """Envia os eventos ainda não encaminhados ao SIEM e avança o cursor só se
    o destino confirmou. Retorna um resumo (nunca levanta).

    CP-SD Fase 6H: o envio real (sender + avanço de cursor) passa pelo
    Control Plane — RBAC nega sem tocar rede; lab/replay vira DRY_RUN_ONLY
    (nunca chama requests.post). ALLOW executa e só avança o cursor se o
    destino confirmar, exatamente como antes.

    CP-SD Fase 6K: se a última tentativa foi DENY/DRY_RUN_ONLY para a MESMA
    combinação de modo/actor/role e o cooldown não expirou, retorna cedo sem
    consultar o Control Plane de novo — não audita, não avança cursor, não
    chama sender. O lote real continua intacto para quando a causa (RBAC ou
    modo) for corrigida."""
    if not is_enabled():
        return "SIEM desligado (SIEM_MODE=off ou SIEM_URL vazio)."
    sender = _SENDERS.get(SIEM_MODE)
    if sender is None:
        return f"SIEM_MODE inválido: {SIEM_MODE!r} (use elastic|splunk|webhook)."

    last = get_siem_cursor()
    rows = get_events_after_id(last, SIEM_BATCH)
    if not rows:
        return "SIEM: nada novo para enviar."

    effective = _effective_principal()
    op_mode = operating_mode.get_operating_mode()

    blocked = get_siem_blocked_state()
    if blocked and _blocked_state_still_applies(blocked, effective.actor, effective.role, op_mode):
        remaining = max(0, int(_seconds_until_cooldown_expires(blocked["blocked_at"])))
        return (f"SIEM: envio ainda bloqueado por governança ({blocked['decision']}); "
                f"reavaliação em cooldown (faltam ~{remaining}s).")

    docs = [_event_to_doc(r) for r in rows]
    candidate_cursor = rows[-1][0]

    def _do_send(mode: str, batch_size: int, last_cursor, new_cursor, destination_type: str) -> str:
        try:
            ok = sender(docs)
        except (requests.RequestException, ValueError) as exc:
            log_event("siem_forward_error", None, f"mode={SIEM_MODE} error={exc!r}", action_taken="falhou")
            return f"SIEM: falha ao enviar ({exc}). Cursor mantido; tenta de novo no próximo ciclo."
        if not ok:
            log_event("siem_forward_error", None, f"mode={SIEM_MODE} destino recusou", action_taken="falhou")
            return "SIEM: o destino recusou o lote. Cursor mantido."
        set_siem_cursor(new_cursor)
        return f"SIEM: {len(docs)} evento(s) enviados ({SIEM_MODE}); cursor em {new_cursor}."

    with _siem_principal_context():
        req = cp.make_request(
            "siem.forward_events", target="siem",
            params={
                "mode": SIEM_MODE,
                "batch_size": len(docs),
                "last_cursor": last,
                "new_cursor": candidate_cursor,
                "destination_type": SIEM_MODE,
            },
        )
        res = cp.request_action(req, executor=_do_send, tool_name="cp_siem_forward_events")

    # CP-SD Fase 6K: bookkeeping do cooldown — DENY/DRY_RUN registra o
    # bloqueio (com a identidade/modo desta tentativa); qualquer outro
    # desfecho (ALLOW com sucesso OU com falha de sender/exceção) limpa,
    # porque a POLICY permitiu — problema de rede/destino não é bloqueio de
    # governança e não deve entrar em cooldown de reavaliação.
    if res.status.value in _BLOCKED_STATUSES:
        set_siem_blocked_state(
            "siem.forward_events", res.status.value, op_mode, effective.actor, effective.role,
            datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        )
    else:
        clear_siem_blocked_state()

    if res.status is cp.ActionStatus.DENIED:
        return f"SIEM: envio NEGADO pela governança: {res.output}"

    if res.status is cp.ActionStatus.DRY_RUN:
        return f"SIEM: [DRY-RUN] envio não realizado ({res.output})"

    if res.status is cp.ActionStatus.FAILED:
        return f"SIEM: falha inesperada ao processar o envio: {res.output}"

    return res.output


def describe_status() -> str:
    if SIEM_MODE == "off":
        return "SIEM: desligado (SIEM_MODE=off)."
    cursor = get_siem_cursor()
    pending = len(get_events_after_id(cursor, SIEM_BATCH))
    cfg = "configurado" if SIEM_URL else "⚠️ SEM SIEM_URL"
    return (f"SIEM: modo={SIEM_MODE} ({cfg}), cursor no evento {cursor}, "
            f"{pending} evento(s) na fila (lote {SIEM_BATCH}).")
