"""Case management / incidentes (Prioridade 6).

Fundação de incident management: agrega evidências, linha do tempo, ações
tomadas e eventos relacionados num CASO com ciclo de vida. Tudo auditado na hash
chain; notas/evidências passam por redaction (nunca guardar segredo em claro).

Ciclo de vida do status:
    open → investigating → contained → resolved | false_positive

O rótulo público do incidente é derivado do id interno: INC-0001. As funções
aceitam tanto o int (7) quanto o rótulo ("INC-0007" / "inc-7" / "7").
"""

import json

import config
from core.redaction import redact
from database.db import (
    append_incident_list,
    create_incident,
    get_incident,
    list_incidents,
    log_event,
    update_incident_fields,
)

SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical")
STATUSES: tuple[str, ...] = ("open", "investigating", "contained", "resolved", "false_positive")
_TERMINAL: tuple[str, ...] = ("resolved", "false_positive")


def _ref(incident_id: int) -> str:
    return f"INC-{incident_id:04d}"


def _parse_id(incident_ref) -> int | None:
    """Aceita 7, '7', 'INC-0007', 'inc-7' → 7."""
    if isinstance(incident_ref, int):
        return incident_ref
    s = str(incident_ref).strip().upper().removeprefix("INC-").lstrip("0") or "0"
    try:
        return int(s)
    except ValueError:
        return None


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _ts_entry(text: str) -> dict:
    return {"at": _now(), "note": redact(text)}


def open_incident(title: str, severity: str = "medium", owner: str = "",
                  related_ip: str = "", related_asset: str = "") -> str:
    """Abre um incidente. severity: low|medium|high|critical."""
    severity = (severity or "medium").strip().lower()
    if severity not in SEVERITIES:
        return f"Severidade inválida: {severity}. Use {', '.join(SEVERITIES)}."
    iid = create_incident(redact(title), severity, owner, related_ip, related_asset)
    append_incident_list(iid, "timeline", _ts_entry(f"incidente aberto (severidade {severity})"))
    log_event("incident_opened", related_ip or None,
              f"{_ref(iid)} sev={severity} title={redact(title)!r}", action_taken="aberto")
    return f"Incidente {_ref(iid)} aberto: {redact(title)} (severidade {severity})."


def set_incident_status(incident_ref, status: str) -> str:
    """Muda o status do incidente. resolved/false_positive carimbam resolved_at."""
    iid = _parse_id(incident_ref)
    status = (status or "").strip().lower()
    if status not in STATUSES:
        return f"Status inválido: {status}. Use {', '.join(STATUSES)}."
    if iid is None or get_incident(iid) is None:
        return f"Incidente {incident_ref} não encontrado."
    update_incident_fields(iid, status=status)
    append_incident_list(iid, "timeline", _ts_entry(f"status → {status}"))
    log_event("incident_status_changed", None, f"{_ref(iid)} status={status}", action_taken=status)
    extra = " (encerrado)" if status in _TERMINAL else ""
    return f"Incidente {_ref(iid)} agora está '{status}'{extra}."


def assign_incident(incident_ref, owner: str) -> str:
    iid = _parse_id(incident_ref)
    if iid is None or get_incident(iid) is None:
        return f"Incidente {incident_ref} não encontrado."
    update_incident_fields(iid, owner=owner)
    append_incident_list(iid, "timeline", _ts_entry(f"atribuído a {owner}"))
    log_event("incident_assigned", None, f"{_ref(iid)} owner={owner}", action_taken="atribuído")
    return f"Incidente {_ref(iid)} atribuído a {owner}."


def add_note(incident_ref, note: str) -> str:
    iid = _parse_id(incident_ref)
    if iid is None or not append_incident_list(iid, "timeline", _ts_entry(note)):
        return f"Incidente {incident_ref} não encontrado."
    return f"Nota adicionada ao incidente {_ref(iid)}."


def add_evidence(incident_ref, evidence: str) -> str:
    iid = _parse_id(incident_ref)
    if iid is None or not append_incident_list(iid, "evidence", _ts_entry(evidence)):
        return f"Incidente {incident_ref} não encontrado."
    return f"Evidência registrada no incidente {_ref(iid)}."


def record_action(incident_ref, action: str) -> str:
    iid = _parse_id(incident_ref)
    if iid is None or not append_incident_list(iid, "actions_taken", _ts_entry(action)):
        return f"Incidente {incident_ref} não encontrado."
    log_event("incident_action_recorded", None, f"{_ref(iid)} action={redact(action)!r}",
              action_taken="ação registrada")
    return f"Ação registrada no incidente {_ref(iid)}."


def link_event(incident_ref, event_id: int) -> str:
    iid = _parse_id(incident_ref)
    if iid is None or not append_incident_list(iid, "event_ids", int(event_id)):
        return f"Incidente {incident_ref} não encontrado."
    return f"Evento {event_id} vinculado ao incidente {_ref(iid)}."


def _load(col_json: str) -> list:
    try:
        return json.loads(col_json) if col_json else []
    except (json.JSONDecodeError, TypeError):
        return []


def incident_report(incident_ref) -> str:
    """Relatório completo de um incidente (timeline, evidências, ações)."""
    iid = _parse_id(incident_ref)
    row = get_incident(iid) if iid is not None else None
    if row is None:
        return f"Incidente {incident_ref} não encontrado."
    (rid, title, severity, status, owner, related_ip, related_asset, event_ids,
     timeline, evidence, actions, created_at, updated_at, resolved_at) = row
    lines = [
        f"{_ref(rid)} — {title}",
        f"  severidade: {severity} | status: {status} | responsável: {owner or '—'}",
        f"  IP: {related_ip or '—'} | ativo: {related_asset or '—'}",
        f"  aberto: {created_at[:16]} | atualizado: {updated_at[:16]}"
        + (f" | resolvido: {resolved_at[:16]}" if resolved_at else ""),
    ]
    evs = _load(event_ids)
    if evs:
        lines.append(f"  eventos vinculados: {', '.join(str(e) for e in evs)}")
    tl = _load(timeline)
    if tl:
        lines.append("  linha do tempo:")
        lines += [f"    [{e.get('at', '')[:16]}] {e.get('note', '')}" for e in tl]
    ev = _load(evidence)
    if ev:
        lines.append("  evidências:")
        lines += [f"    [{e.get('at', '')[:16]}] {e.get('note', '')}" for e in ev]
    ac = _load(actions)
    if ac:
        lines.append("  ações tomadas:")
        lines += [f"    [{e.get('at', '')[:16]}] {e.get('note', '')}" for e in ac]
    return "\n".join(lines)


_ACTIVE_STATUSES: tuple[str, ...] = ("open", "investigating", "contained")


def _find_active(ip: str, kind: str) -> int | None:
    """Incidente ainda ativo do mesmo IP e tipo (dedupe do auto-incidente)."""
    for row in list_incidents(limit=200):
        rid, title, _sev, status, _owner, related_ip = row[0], row[1], row[2], row[3], row[4], row[5]
        if status in _ACTIVE_STATUSES and related_ip == ip and title.startswith(f"[{kind}]"):
            return rid
    return None


def auto_open_from_event(kind: str, ip: str, detail: str = "", severity: str = "high",
                         title: str = "") -> int | None:
    """Abre (ou reaproveita) um incidente a partir de um evento de ataque. Opt-in
    via AUTO_INCIDENT_ENABLED; idempotente por (ip, kind): se já houver um
    incidente ativo, só anota e devolve o id existente. Retorna o id ou None."""
    if not getattr(config, "AUTO_INCIDENT_ENABLED", False):
        return None
    existing = _find_active(ip, kind)
    if existing is not None:
        add_note(existing, f"novo evento [{kind}]" + (f": {detail}" if detail else ""))
        return existing
    t = title or f"[{kind}] {detail or kind} ({ip})"
    iid = create_incident(redact(t), severity, related_ip=ip)
    append_incident_list(iid, "timeline",
                         _ts_entry(f"incidente aberto automaticamente por evento [{kind}]: {detail}"))
    log_event("incident_auto_opened", ip or None, f"{_ref(iid)} kind={kind} sev={severity}",
              action_taken="auto-aberto")
    return iid


def list_incidents_report(status: str | None = None, limit: int = 50) -> str:
    rows = list_incidents(status, limit)
    if not rows:
        return f"Nenhum incidente{f' com status {status}' if status else ''}."
    lines = [f"Incidentes ({len(rows)}{f', status={status}' if status else ''}):"]
    for row in rows:
        rid, title, severity, st, owner = row[0], row[1], row[2], row[3], row[4]
        lines.append(f"  {_ref(rid)} [{severity}/{st}] {title}" + (f" — {owner}" if owner else ""))
    return "\n".join(lines)
