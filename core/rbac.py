"""RBAC mínimo (Prioridade 4) — papéis e permissões determinísticos.

Ainda não há sistema de usuários reais: toda ação sem ator explícito é atribuída
ao ator padrão (config.DEFAULT_ACTOR = 'local_admin', role config.DEFAULT_ROLE =
'admin'), preservando o comportamento atual com o token único. A estrutura já
está pronta para evoluir para usuários/tokens por papel depois.

Permissões são strings de capacidade ligadas ao `required_permission` de cada
action_type da policy engine. Um papel concede um conjunto de permissões, com
suporte a wildcard total ("*") e por prefixo ("defense.*").

RBAC é só UMA camada: mesmo que um papel TENHA a permissão, a policy engine
ainda aplica risco, toggles (ALLOW_*), modo operacional e aprovação humana. Ou
seja, ter a permissão é necessário, não suficiente, para ações sensíveis.
"""

import config

ROLES: tuple[str, ...] = ("admin", "soc_analyst", "noc_operator", "auditor", "readonly")

# Conjunto de permissões por papel. "*" = tudo; "<prefixo>.*" = todo o grupo.
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {"*"},
    # SOC: leitura, auditoria, defesa e investigação. Exploração ofensiva NÃO é
    # concedida por padrão (fica como admin + toggle + aprovação) — conservador.
    "soc_analyst": {"read", "audit", "defense.*", "investigate.*"},
    # NOC: operação de rede limitada + bloqueio/desbloqueio de IP defensivo.
    "noc_operator": {"read", "noc.*", "defense.block_ip", "defense.unblock_ip"},
    # Auditor: leitura + verificação/exportação de auditoria.
    "auditor": {"read", "audit"},
    # Read-only: só leitura.
    "readonly": {"read"},
}


def default_actor() -> str:
    return getattr(config, "DEFAULT_ACTOR", "local_admin")


def default_role() -> str:
    role = getattr(config, "DEFAULT_ROLE", "admin")
    return role if role in ROLES else "admin"


def normalize_role(role: str | None) -> str:
    r = (role or "").strip().lower()
    return r if r in ROLES else default_role()


def has_permission(role: str | None, permission: str) -> bool:
    """True se o papel concede a permissão (exata, por prefixo, ou wildcard)."""
    if not permission:
        return True  # ação sem permissão exigida (ex.: read puro não rotulado)
    perms = ROLE_PERMISSIONS.get(normalize_role(role), set())
    if "*" in perms:
        return True
    if permission in perms:
        return True
    for p in perms:
        if p.endswith(".*") and permission.startswith(p[:-1]):  # "defense." prefixo
            return True
    return False


def describe_role(role: str) -> str:
    role = normalize_role(role)
    perms = sorted(ROLE_PERMISSIONS.get(role, set()))
    return f"{role}: {', '.join(perms) or '—'}"
