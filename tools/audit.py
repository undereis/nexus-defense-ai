"""Verificação de integridade da trilha de auditoria (hash chain).

database/db.log_event() encadeia cada evento com o hash do anterior.
Este módulo recalcula a cadeia inteira e compara com o que está
armazenado: se algum evento foi alterado, apagado ou inserido fora de
ordem depois de gravado, a cadeia quebra a partir desse ponto — exatamente
o que dá a um log de auditoria a propriedade de "à prova de violação"
sem precisar de infraestrutura externa (assinatura, blockchain real, etc).

Eventos gravados ANTES desta funcionalidade existir não têm hash (NULL)
e são tratados como uma "era legada" — não quebram a cadeia, mas também
não têm garantia de integridade anterior a este ponto.
"""

from dataclasses import dataclass

from database.db import GENESIS_HASH, _compute_entry_hash, get_all_events


@dataclass
class AuditResult:
    total_events: int
    verified_events: int
    legacy_events: int
    intact: bool
    broken_at_id: int | None


def verify_chain() -> AuditResult:
    rows = get_all_events()
    prev_hash = GENESIS_HASH
    verified = 0
    legacy = 0

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

        prev_hash = stored_entry
        verified += 1

    return AuditResult(
        total_events=len(rows),
        verified_events=verified,
        legacy_events=legacy,
        intact=True,
        broken_at_id=None,
    )


def describe(result: AuditResult) -> str:
    if result.total_events == 0:
        return "Nenhum evento de auditoria registrado ainda."

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
