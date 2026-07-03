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

import re
from dataclasses import dataclass

import config

ROLES: tuple[str, ...] = (
    "admin", "soc_analyst", "noc_operator", "auditor", "readonly",
    # CP-SD Fase 5A: papel dedicado a contas de SERVIÇO (jobs automáticos
    # internos — ver SERVICE_*_PRINCIPAL abaixo). Desacoplado de "readonly"
    # de propósito: mesmo nível de privilégio hoje (só "read"), mas fases
    # futuras podem conceder permissão específica por serviço sem afetar o
    # que usuários humanos readonly podem fazer.
    "service",
)


@dataclass(frozen=True)
class Principal:
    """Identidade EFETIVA de quem pede uma ação: `actor` (quem — ex.: 'user:Ana',
    'api:main', 'local_admin') + `role` (papel RBAC). Tipo canônico reutilizado
    pela API (resolução do token) e propagado ao Control Plane (Fase 2)."""

    actor: str
    role: str

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
    # Serviço automático interno (CP-SD Fase 5A): conservador por padrão —
    # igual readonly. NUNCA "*"/admin. Fases futuras que migrarem cada loop
    # de fato decidem a permissão mínima ADICIONAL necessária por serviço.
    "service": {"read"},
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


# --------------------------- Service Principals (CP-SD Fase 5A) ---------------------------
#
# Identidade EXPLÍCITA para jobs automáticos internos (loops de main.py: monitor,
# reconcile, billing, playbook, honeypot, honeytoken, watchdog, siem, o reporter de
# AbuseIPDB...). Hoje esses jobs, quando chamam ask_agent sem `principal=`, caem no
# fallback local_admin/admin (ver ask_agent). O objetivo desta fase é só PREPARAR o
# terreno — nenhum loop de main.py foi migrado ainda para usar estes Principals;
# quando cada loop for migrado (fase futura, pequena, um de cada vez), ele importa
# a constante correspondente e passa `principal=SERVICE_X_PRINCIPAL` ao ask_agent
# (ou usa `core.control_plane.principal_context(SERVICE_X_PRINCIPAL)` diretamente).
#
# Mesmo padrão de namespace `<categoria>:<nome>` já usado pelos Principals de
# integração da Fase 2B (`integration:telegram`, `integration:slack`). Todos usam o
# papel "service" (conservador, ver ROLE_PERMISSIONS acima) — nenhum é admin, nenhum
# recebe "*".

_SERVICE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def service_principal(name: str) -> Principal:
    """Principal de um serviço automático interno: actor 'service:<name>',
    papel 'service' (conservador — nunca admin/"*", ver ROLE_PERMISSIONS).

    `name` é validado (não é entrada de usuário final, mas vai para
    auditoria/log/hash chain — nome livre poderia poluir a trilha ou confundir
    operação): minúsculas/dígitos/hífen/underscore, começando por
    letra/dígito, até 64 caracteres. Sem isso, um nome com ':'/'/'/quebra de
    linha poderia forjar um actor parecido com outro papel na auditoria."""
    if not _SERVICE_NAME_RE.match(name or ""):
        raise ValueError(
            f"nome de serviço inválido: {name!r}. Use letras minúsculas, dígitos, "
            "'-' ou '_', começando por letra/dígito (regex "
            f"{_SERVICE_NAME_RE.pattern!r})."
        )
    return Principal(f"service:{name}", "service")


SERVICE_MONITOR_PRINCIPAL = service_principal("monitor")
SERVICE_PROACTIVE_AUDIT_PRINCIPAL = service_principal("proactive-audit")
SERVICE_RECONCILE_PRINCIPAL = service_principal("reconcile")
SERVICE_BILLING_PRINCIPAL = service_principal("billing")
SERVICE_PLAYBOOK_PRINCIPAL = service_principal("playbook")
SERVICE_HONEYPOT_PRINCIPAL = service_principal("honeypot")
SERVICE_HONEYTOKEN_PRINCIPAL = service_principal("honeytoken")
SERVICE_ABUSEIPDB_REPORTER_PRINCIPAL = service_principal("abuseipdb-reporter")
SERVICE_WATCHDOG_PRINCIPAL = service_principal("watchdog")
SERVICE_SIEM_PRINCIPAL = service_principal("siem")
