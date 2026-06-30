"""Assinatura HMAC dos eventos de auditoria (Prioridade 7) — canal LATERAL.

A hash chain (database.db.log_event) garante INTEGRIDADE (não dá para alterar um
evento no meio sem quebrar a cadeia). Ela não garante AUTENTICIDADE: quem
conseguir reescrever a tabela inteira pode recomputar uma cadeia válida. A
assinatura HMAC fecha isso: cada `entry_hash` é assinado com um segredo
(`AUDIT_HMAC_SECRET`) que NÃO está na cadeia — sem o segredo não dá para forjar
assinaturas válidas, então uma cadeia reescrita seria detectada na verificação.

Importante (não quebra nada):
- NÃO altera a tabela `events` nem `_compute_entry_hash`; assina num sidecar
  (`event_signatures`). Eventos antigos sem assinatura continuam válidos.
- Desligado por padrão (`AUDIT_HMAC_SECRET` vazio): `sign_new_events` é no-op e
  `verify_signatures` informa "desabilitado".
"""

import hashlib
import hmac
import json
from dataclasses import dataclass, field

import config
from database.db import (
    add_event_signature,
    get_all_events,
    get_signed_events,
    get_unsigned_events,
)

ALGO = "hmac-sha256"


def is_enabled() -> bool:
    return bool((getattr(config, "AUDIT_HMAC_SECRET", "") or "").strip())


def _secret_bytes() -> bytes:
    return (getattr(config, "AUDIT_HMAC_SECRET", "") or "").encode("utf-8")


def compute_signature(entry_hash: str) -> str:
    return hmac.new(_secret_bytes(), (entry_hash or "").encode("utf-8"), hashlib.sha256).hexdigest()


def sign_new_events() -> int:
    """Assina todos os eventos com hash ainda não assinados. No-op se desligado.
    Retorna quantos foram assinados."""
    if not is_enabled():
        return 0
    n = 0
    for event_id, entry_hash in get_unsigned_events():
        add_event_signature(event_id, compute_signature(entry_hash), ALGO)
        n += 1
    return n


@dataclass
class SignatureAudit:
    enabled: bool
    checked: int = 0
    valid: int = 0
    mismatched: list[int] = field(default_factory=list)

    @property
    def intact(self) -> bool:
        return self.enabled and not self.mismatched


def verify_signatures() -> SignatureAudit:
    """Recalcula e compara as assinaturas. Mismatch = evento adulterado depois de
    assinado (ou segredo trocado)."""
    if not is_enabled():
        return SignatureAudit(enabled=False)
    result = SignatureAudit(enabled=True)
    for event_id, entry_hash, signature in get_signed_events():
        if hmac.compare_digest(compute_signature(entry_hash), signature or ""):
            result.valid += 1
        else:
            result.mismatched.append(event_id)
        result.checked += 1
    return result


def describe(result: SignatureAudit) -> str:
    if not result.enabled:
        return ("Assinatura HMAC da auditoria DESLIGADA (AUDIT_HMAC_SECRET vazio). "
                "A hash chain continua protegendo a integridade; defina o segredo "
                "para adicionar autenticidade.")
    if result.intact:
        return f"Assinaturas HMAC INTACTAS: {result.valid}/{result.checked} evento(s) verificados."
    return (f"⚠️ {len(result.mismatched)} assinatura(s) NÃO conferem "
            f"(eventos {result.mismatched[:10]}...). Adulteração ou troca de segredo — investigue.")


def export_events_json() -> str:
    """Serializa toda a trilha de eventos (com hash chain e assinatura quando
    houver) como JSON — para arquivamento externo / análise forense / ingestão."""
    sig_map = {row[0]: row[2] for row in get_signed_events()}
    out = []
    for (eid, ts, etype, ip, detail, action, prev_hash, entry_hash) in get_all_events():
        out.append({
            "id": eid, "timestamp": ts, "event_type": etype, "source_ip": ip,
            "detail": detail, "action_taken": action,
            "prev_hash": prev_hash, "entry_hash": entry_hash,
            "signature": sig_map.get(eid),
        })
    return json.dumps(out, ensure_ascii=False, indent=2)


def export_events_to_workdir() -> str:
    """Escreve a trilha em JSON num arquivo dentro de WORKDIR/exports (caminho
    seguro, sem input do usuário) e retorna um resumo."""
    from datetime import datetime, timezone

    base = config.WORKDIR / "exports"
    base.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = base / f"audit_{stamp}.json"
    data = export_events_json()
    path.write_text(data, encoding="utf-8")
    count = data.count('"id":')
    return f"Trilha de auditoria exportada: {path} ({count} evento(s))."
