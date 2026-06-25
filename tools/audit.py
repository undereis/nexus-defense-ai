"""Verificação de integridade da trilha de auditoria (hash chain).

database/db.log_event() encadeia cada evento com o hash do anterior.
Este módulo recalcula a cadeia inteira e compara com o que está
armazenado: se algum evento foi alterado, apagado ou inserido fora de
ordem NO MEIO da cadeia, isso quebra a partir desse ponto.

LIMITE CONHECIDO DO HASH CHAIN PURO: remover eventos do FINAL da cadeia
(truncamento) não quebra a verificação interna — os eventos restantes
continuam internamente consistentes entre si, só "termina mais cedo".
Por isso existe create_checkpoint(): periodicamente salva (e tenta
enviar para FORA do banco, via notify) o id e hash do último evento.
Se depois disso algum desses eventos desaparecer, a comparação contra
o checkpoint denuncia o truncamento — mas só é prova real se o
checkpoint foi de fato entregue externamente (sent_externally=True);
um checkpoint que só existe no mesmo SQLite pode ser apagado junto.

Eventos gravados ANTES desta funcionalidade existir não têm hash (NULL)
e são tratados como uma "era legada" — não quebram a cadeia, mas também
não têm garantia de integridade anterior a este ponto.
"""

from dataclasses import dataclass

from database.db import (
    GENESIS_HASH,
    _compute_entry_hash,
    get_all_events,
    get_latest_audit_checkpoint,
    save_audit_checkpoint,
)


@dataclass
class AuditResult:
    total_events: int
    verified_events: int
    legacy_events: int
    intact: bool
    broken_at_id: int | None
    truncated: bool = False
    checkpoint_note: str = ""


def verify_chain() -> AuditResult:
    rows = get_all_events()
    prev_hash = GENESIS_HASH
    verified = 0
    legacy = 0
    seen_ids_with_hash: dict[int, str] = {}

    for row in rows:
        event_id, timestamp, event_type, source_ip, detail, action_taken, stored_prev, stored_entry = row

        if stored_entry is None:
            # Evento de antes do hash chain existir: não verificável, mas
            # não conta como violação — é só "fora do período coberto".
            legacy += 1
            continue

        expected = _compute_entry_hash(prev_hash, timestamp, event_type, source_ip, detail, action_taken)
        if stored_prev != prev_hash or stored_entry != expected:
            return AuditResult(
                total_events=len(rows),
                verified_events=verified,
                legacy_events=legacy,
                intact=False,
                broken_at_id=event_id,
            )

        seen_ids_with_hash[event_id] = stored_entry
        prev_hash = stored_entry
        verified += 1

    truncated = False
    checkpoint_note = ""
    checkpoint = get_latest_audit_checkpoint()
    if checkpoint:
        created_at, ck_count, ck_last_id, ck_last_hash, sent_externally = checkpoint
        if seen_ids_with_hash.get(ck_last_id) != ck_last_hash:
            truncated = True
            externally_note = (
                "checkpoint foi enviado externamente — isto é prova forte de adulteração."
                if sent_externally
                else "checkpoint só existia localmente — indício, não prova definitiva."
            )
            checkpoint_note = (
                f"Checkpoint de {created_at} registrava {ck_count} evento(s) e o evento "
                f"id={ck_last_id} com hash {ck_last_hash[:12]}..., mas esse evento não existe "
                f"mais (ou tem hash diferente) na cadeia atual. {externally_note}"
            )

    return AuditResult(
        total_events=len(rows),
        verified_events=verified,
        legacy_events=legacy,
        intact=not truncated,
        broken_at_id=None,
        truncated=truncated,
        checkpoint_note=checkpoint_note,
    )


def create_checkpoint() -> str:
    """Salva o estado atual (quantos eventos, hash do último) como
    checkpoint, e tenta enviar essa informação para fora do banco local
    via notify (Slack/webhook) — é o que dá proteção real contra
    truncamento, não só o registro local."""
    from tools import notify

    rows = get_all_events()
    hashed_rows = [r for r in rows if r[7] is not None]
    if not hashed_rows:
        return "Nenhum evento com hash ainda — nada para ancorar em checkpoint."

    last = hashed_rows[-1]
    last_event_id, last_entry_hash = last[0], last[7]

    sent = notify.send_notification(
        "Nexus: checkpoint de auditoria",
        f"Eventos totais: {len(rows)} | Último evento id={last_event_id} | "
        f"hash={last_entry_hash}",
    )
    save_audit_checkpoint(len(rows), last_event_id, last_entry_hash, sent_externally=sent)

    if sent:
        return f"Checkpoint criado e enviado externamente (evento id={last_event_id})."
    return (
        f"Checkpoint criado, mas SEM envio externo (evento id={last_event_id}) — "
        "configure NOTIFY_WEBHOOK_URL ou SLACK_BOT_TOKEN para proteção real contra truncamento."
    )


def describe(result: AuditResult) -> str:
    if result.total_events == 0:
        return "Nenhum evento de auditoria registrado ainda."

    if result.truncated:
        return f"⚠️ TRUNCAMENTO DETECTADO na trilha de auditoria: {result.checkpoint_note}"

    if result.intact:
        return (
            f"Trilha de auditoria INTACTA: {result.verified_events} evento(s) verificado(s) "
            f"por hash chain" + (f", {result.legacy_events} evento(s) legado(s) sem hash" if result.legacy_events else "") +
            f", de {result.total_events} total. Nenhuma adulteração detectada."
        )

    return (
        f"⚠️ VIOLAÇÃO DE INTEGRIDADE DETECTADA: a cadeia de hash quebra no evento "
        f"id={result.broken_at_id}. {result.verified_events} evento(s) antes dele "
        f"estão intactos. Isso significa que um evento foi alterado, apagado ou "
        f"inserido fora de ordem depois de gravado — investigue imediatamente."
    )
