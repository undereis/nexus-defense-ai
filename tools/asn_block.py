"""Bloqueio de ASN inteiro — bloqueia todos os prefixos IP de uma
organização/rede autônoma quando o padrão de ataque vem repetidamente
da mesma rede.

BARREIRA DE SEGURANÇA: esta é a ação de MAIOR BLAST RADIUS da Nexus.
Bloquear um ASN pode afetar qualquer cliente legítimo do mesmo provedor
— um /16 de uma cloud pública pode ter dezenas de milhares de usuários
legítimos. Portanto:
  1. ALLOW_ASN_BLOCK=true no .env é pré-requisito (habilitação deliberada).
  2. SEMPRE passa pelo gate de confirmação de tools/risk.py com código
     fora de banda — nunca executa no mesmo turno em que é proposto.
  3. Documentado explicitamente em todo ponto de entrada.

NUNCA VALIDADO CONTRA ASN REAL em ambiente de produção — a lógica de
consulta de prefixos (RIPEstat) e o bloqueio (pfctl/ipset) estão testados
isoladamente, mas o fluxo completo foi validado apenas com mocks.
"""

import json
import re

from config import ALLOW_ASN_BLOCK
from database.db import (
    get_asn_block,
    list_asn_blocks,
    log_event,
    record_asn_block,
    remove_asn_block,
)
from tools import firewall
from tools import risk as risk_gate
from tools.whois_lookup import get_asn_prefixes

_ASN_RE = re.compile(r"^(?:AS|as)?(\d{1,10})$")


def _normalize_asn(asn: str) -> str:
    match = _ASN_RE.match(asn.strip())
    if not match:
        raise ValueError(f"ASN inválido: {asn!r}. Use número ou 'AS15169'.")
    return f"AS{match.group(1)}"


def _execute_block(asn: str, description: str) -> str:
    """Bloqueia todos os prefixos de um ASN. Registrado no gate via
    risk_gate.register_action — NUNCA chamado diretamente pelo agente."""
    prefixes = get_asn_prefixes(asn)
    if not prefixes:
        return f"{asn}: nenhum prefixo encontrado para bloquear."
    blocked, failed = [], []
    for prefix in prefixes:
        result = firewall.block_cidr(prefix, f"ASN block: {asn} ({description})")
        if "bloqueado" in result:
            blocked.append(prefix)
        else:
            failed.append(prefix)
    record_asn_block(asn, description, prefixes)
    log_event(
        "asn_block_executed", asn,
        f"{len(blocked)} prefixos bloqueados, {len(failed)} falhas",
        action_taken="bloqueado",
    )
    parts = [
        f"{asn} ({description or 'sem descrição'}): "
        f"{len(blocked)}/{len(prefixes)} prefixo(s) bloqueados."
    ]
    if failed:
        sample = ", ".join(failed[:5])
        parts.append(f"  Falhas ({len(failed)}): {sample}{'…' if len(failed) > 5 else ''}")
    return "\n".join(parts)


def request_asn_block(asn: str, description: str = "") -> str:
    """Propõe bloquear todos os prefixos IP de um ASN inteiro — coloca no
    gate de confirmação (código fora de banda obrigatório).

    ALLOW_ASN_BLOCK=true deve estar no .env antes de chamar isto."""
    if not ALLOW_ASN_BLOCK:
        return (
            "ALLOW_ASN_BLOCK não habilitado no .env — habilite deliberadamente "
            "antes de usar bloqueio por ASN (ação de blast radius muito alto)."
        )
    try:
        asn = _normalize_asn(asn)
    except ValueError as exc:
        return str(exc)

    existing = get_asn_block(asn)
    if existing:
        desc, prefixes_json, blocked_at = existing
        count = len(json.loads(prefixes_json))
        return f"{asn} já está bloqueado desde {blocked_at} ({count} prefixo(s))."

    prefixes = get_asn_prefixes(asn)
    if not prefixes:
        return f"{asn}: nenhum prefixo público encontrado (ASN inválido ou sem anúncio BGP ativo)."

    sample = ", ".join(prefixes[:5]) + ("…" if len(prefixes) > 5 else "")
    summary = (
        f"Bloquear ASN {asn} ({description or 'sem descrição'}): "
        f"{len(prefixes)} prefixo(s) — {sample}. "
        "IMPACTO ALTO: todo tráfego legítimo dessa rede será bloqueado também."
    )
    return risk_gate.request_confirmation(
        "asn_block_execute",
        summary,
        kb_query="autonomous system network block BGP prefix ASN",
        asn=asn,
        description=description,
    )


def unblock_asn(asn: str) -> str:
    """Remove o bloqueio de um ASN previamente bloqueado — desfaz TODOS os
    CIDRs que foram adicionados ao firewall quando o ASN foi bloqueado."""
    try:
        asn = _normalize_asn(asn)
    except ValueError as exc:
        return str(exc)

    existing = get_asn_block(asn)
    if not existing:
        return f"{asn} não está na lista de ASNs bloqueados."

    _, prefixes_json, _ = existing
    prefixes = json.loads(prefixes_json)
    unblocked, failed = [], []
    for prefix in prefixes:
        result = firewall.unblock_cidr(prefix)
        if "desbloqueado" in result:
            unblocked.append(prefix)
        else:
            failed.append(prefix)

    remove_asn_block(asn)
    log_event(
        "asn_block_removed", asn,
        f"{len(unblocked)} prefixos desbloqueados, {len(failed)} falhas",
        action_taken="desbloqueado",
    )
    return f"{asn}: {len(unblocked)}/{len(prefixes)} prefixo(s) desbloqueados."


def list_blocked_asns() -> str:
    """Lista os ASNs com bloqueio ativo e quantos prefixos foram bloqueados."""
    rows = list_asn_blocks()
    if not rows:
        return "Nenhum ASN bloqueado atualmente."
    lines = ["ASNs bloqueados:"]
    for asn, description, prefix_count, blocked_at in rows:
        lines.append(
            f"  {asn} — {description or 'sem descrição'} "
            f"({prefix_count} prefixos, bloqueado em {blocked_at})"
        )
    return "\n".join(lines)
