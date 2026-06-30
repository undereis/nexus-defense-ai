"""Inventário de ativos AUTORIZADOS (Prioridade 3) + verificação de alvo.

Aqui ficam os ativos que um operador autorizou EXPLICITAMENTE como alvo de ação
sensível (com tipo, ambiente real/lab, escopo de ações e janela de validade).
É distinto de:
  - tools/infrastructure.py  → blocos da PRÓPRIA rede (protegidos de auto-bloqueio);
  - tools/asset_inventory.py → ativos DESCOBERTOS por scan (não necessariamente autorizados);
  - tabela authorized_assets → agendamento de auditoria proativa.

A função central, `check_target`, é consultada pela policy engine. Ela aplica:

  1. TRAVAS DE SEGURANÇA DURAS (sempre, independente de config): nunca autoriza
     ação que altere estado contra a própria infraestrutura crítica
     (tools/infrastructure.is_critical_ip), loopback (127/8) ou endereço
     reservado/multicast. Mesma filosofia de _is_safe_to_isolate/_is_safe_to_block.
  2. Match no inventário: ativo habilitado, dentro da validade e com a ação no
     escopo.
  3. Compatibilidade: se o alvo não está no inventário e
     REQUIRE_ASSET_AUTHORIZATION=false (padrão), é permitido porém AUDITADO como
     "fora do inventário". Com o toggle true, sem cadastro → negado.
"""

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone

import config
from database.db import (
    get_asset,
    list_registered_assets,
    register_asset,
    remove_asset,
    set_asset_enabled,
)
from tools import infrastructure

ASSET_TYPES: tuple[str, ...] = (
    "network", "host", "mikrotik", "subscriber", "server", "sensor", "honeypot", "lab",
)


# --------------------------- classificação de IP ---------------------------

def classify_ip(value: str) -> str:
    """Categoria de um IP: 'loopback' | 'private' | 'reserved' | 'public' |
    'not_ip'. Espelha (em Python) a detecção do cliente Tauri (classifyIp)."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return "not_ip"
    if addr.is_loopback:
        return "loopback"
    if addr.is_private and not addr.is_loopback and not addr.is_link_local:
        return "private"
    if addr.is_link_local or addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return "reserved"
    return "public"


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


# ------------------------------- resultado --------------------------------

@dataclass
class TargetCheck:
    authorized: bool          # decisão final desta camada
    hard_denied: bool         # trava de segurança dura (sobrepõe tudo)
    matched: bool             # houve match explícito no inventário
    reason: str
    asset_id: str | None = None
    ip_class: str = ""


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _within_validity(valid_from: str | None, valid_until: str | None) -> bool:
    now = _now_iso()
    if valid_from and now < valid_from:
        return False
    if valid_until and now > valid_until:
        return False
    return True


def _scope_allows(scope: str, action: str) -> bool:
    scope = (scope or "").strip()
    if scope in ("", "*"):
        return True  # ativo explicitamente cadastrado = autorizado p/ qualquer ação
    allowed = {s.strip() for s in scope.split(",") if s.strip()}
    return action in allowed or "*" in allowed


def _find_matches(target: str, action: str):
    """Ativos habilitados, válidos e no escopo que casam com o alvo."""
    target = (target or "").strip()
    is_ip = classify_ip(target) != "not_ip"
    out = []
    for row in list_registered_assets(enabled_only=True):
        (asset_id, _type, hostname, ip, cidr, _owner, _env, scope,
         valid_from, valid_until, _notes, _enabled, _created, _updated) = row
        match = (
            target == asset_id
            or (ip and target == ip)
            or (hostname and target == hostname)
            or (cidr and is_ip and _ip_in_cidr(target, cidr))
        )
        if not match:
            continue
        if not _within_validity(valid_from, valid_until):
            continue
        if not _scope_allows(scope, action):
            continue
        out.append(row)
    return out


def check_target(target: str, action: str, *, changes_state: bool = True) -> TargetCheck:
    """Verifica se `target` é um alvo autorizado para `action`. A policy engine
    usa o resultado. `changes_state=False` (leitura) afrouxa as travas duras."""
    target = (target or "").strip()
    if not target:
        # Ação sem alvo concreto (ex.: rodar ciclo de billing) — não há o que
        # autorizar aqui; a policy decide pelas outras dimensões.
        return TargetCheck(True, False, False, "sem alvo específico")

    ip_class = classify_ip(target)

    # 1) Travas de segurança duras — só para ações que ALTERAM ESTADO.
    if changes_state:
        if ip_class != "not_ip" and infrastructure.is_critical_ip(target):
            return TargetCheck(
                False, True, False,
                "alvo é infraestrutura PRÓPRIA crítica — nunca sofre ação que altere estado",
                ip_class=ip_class,
            )
        if ip_class == "loopback":
            return TargetCheck(False, True, False, "loopback (127/8) nunca é alvo válido", ip_class=ip_class)
        if ip_class == "reserved":
            return TargetCheck(False, True, False, "endereço reservado/multicast nunca é alvo válido", ip_class=ip_class)

    # 2) Match explícito no inventário.
    matches = _find_matches(target, action)
    if matches:
        return TargetCheck(
            True, False, True,
            f"ativo autorizado no inventário (escopo cobre '{action}')",
            asset_id=matches[0][0], ip_class=ip_class,
        )

    # 3) Sem cadastro: compatibilidade vs. modo estrito.
    if getattr(config, "REQUIRE_ASSET_AUTHORIZATION", False):
        return TargetCheck(
            False, False, False,
            "alvo não está no inventário de ativos autorizados (modo estrito)",
            ip_class=ip_class,
        )
    # Privado não cadastrado em modo permissivo: alerta, mas permite (pode ser lab).
    note = "fora do inventário — permitido por compatibilidade (audite/cadastre o ativo)"
    if ip_class == "private":
        note = "IP privado fora do inventário — permitido por compatibilidade; cadastre o lab/rede própria"
    return TargetCheck(True, False, False, note, ip_class=ip_class)


# --------------------------- API de gerência (tools) ---------------------------

def authorize_asset(
    asset_id: str, asset_type: str, *, hostname: str = "", ip: str = "", cidr: str = "",
    owner: str = "", environment: str = "real", authorized_scope: str = "",
    valid_from: str = "", valid_until: str = "", notes: str = "",
) -> str:
    """Cadastra/atualiza um ativo autorizado. Valida tipo, ambiente e ip/cidr."""
    asset_id = (asset_id or "").strip()
    if not asset_id:
        return "asset_id é obrigatório."
    asset_type = (asset_type or "").strip().lower()
    if asset_type not in ASSET_TYPES:
        return f"Tipo inválido: {asset_type!r}. Use um de {', '.join(ASSET_TYPES)}."
    environment = (environment or "real").strip().lower()
    if environment not in ("real", "lab"):
        return "environment deve ser 'real' ou 'lab'."
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return f"IP inválido: {ip}"
    if cidr:
        try:
            cidr = str(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            return f"CIDR inválido: {cidr}"
    register_asset(
        asset_id, asset_type, hostname=hostname, ip=ip, cidr=cidr, owner=owner,
        environment=environment, authorized_scope=authorized_scope,
        valid_from=valid_from or None, valid_until=valid_until or None,
        notes=notes, enabled=True,
    )
    return f"Ativo '{asset_id}' ({asset_type} | {environment}) autorizado no inventário."


def revoke_asset(asset_id: str) -> str:
    return (
        f"Ativo '{asset_id}' removido do inventário."
        if remove_asset(asset_id)
        else f"Ativo '{asset_id}' não encontrado."
    )


def set_enabled(asset_id: str, enabled: bool) -> str:
    if not set_asset_enabled(asset_id, enabled):
        return f"Ativo '{asset_id}' não encontrado."
    return f"Ativo '{asset_id}' {'habilitado' if enabled else 'desabilitado'}."


def list_authorized_assets() -> str:
    rows = list_registered_assets()
    if not rows:
        return (
            "Inventário de ativos autorizados vazio. Use authorize_asset para cadastrar "
            "redes próprias, labs e alvos autorizados — sem isso, em modo estrito nenhuma "
            "ação sensível executa."
        )
    lines = [f"Ativos autorizados ({len(rows)}):"]
    for row in rows:
        (asset_id, asset_type, hostname, ip, cidr, owner, env, scope,
         valid_from, valid_until, notes, enabled, _c, _u) = row
        loc = ip or cidr or hostname or "—"
        flags = "" if enabled else " [DESABILITADO]"
        window = ""
        if valid_from or valid_until:
            window = f" | validade {valid_from or '…'}→{valid_until or '…'}"
        lines.append(
            f"  [{asset_type}] {asset_id} ({loc}) | env={env} | escopo={scope or '*'}"
            f"{window}{flags}" + (f" — {notes}" if notes else "")
        )
    return "\n".join(lines)


def get_asset_summary(asset_id: str) -> str:
    row = get_asset(asset_id)
    if not row:
        return f"Ativo '{asset_id}' não encontrado."
    (asset_id, asset_type, hostname, ip, cidr, owner, env, scope,
     valid_from, valid_until, notes, enabled, created, updated) = row
    return (
        f"Ativo {asset_id}\n  tipo: {asset_type} | env: {env} | "
        f"{'habilitado' if enabled else 'DESABILITADO'}\n"
        f"  ip: {ip or '—'} | cidr: {cidr or '—'} | hostname: {hostname or '—'}\n"
        f"  owner: {owner or '—'} | escopo: {scope or '*'}\n"
        f"  validade: {valid_from or '…'} → {valid_until or '…'}\n"
        f"  notas: {notes or '—'} (criado {created[:16]}, atualizado {updated[:16]})"
    )
