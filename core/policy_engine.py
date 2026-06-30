"""Policy Engine determinística (Prioridade 2).

Recebe um ActionRequest e devolve um ActionDecision: ALLOW / DENY /
REQUIRE_APPROVAL / DRY_RUN_ONLY. Pura e determinística (mesmo pedido + mesmo
estado de config/inventário ⇒ mesma decisão), fácil de testar.

Avalia, em ordem (deny tem precedência sobre approval):
  1. RBAC          — o papel tem a permissão exigida pela ação?
  2. Segurança dura — alvo é infra própria crítica / loopback / reservado?
  3. Toggle         — a capacidade exige ALLOW_* e ele está ligado?
  4. Engagement ref — engenharia social exige referência de engajamento.
  5. Inventário     — alvo autorizado (ou compatível, conforme config)?
  6. Modo           — em lab/replay, ação que altera estado vira DRY_RUN_ONLY.
  7. Aprovação      — risco alto/crítico ou marcado ⇒ REQUIRE_APPROVAL.
  8. ALLOW.

Política conservadora: o desconhecido é tratado como ação que altera estado
(risco médio), mas sem exigir permissão específica (compatibilidade); ações
ofensivas/infra de alto impacto exigem toggle + aprovação.
"""

from dataclasses import dataclass

import config
from core import operating_mode, rbac
from core.models import ActionDecision, ActionRisk, Decision
from tools import asset_registry


@dataclass(frozen=True)
class ActionSpec:
    required_permission: str
    changes_state: bool
    risk: ActionRisk
    requires_toggle: str = ""        # nome do atributo em config que deve ser True
    requires_approval: bool = False
    needs_engagement_ref: bool = False


# Catálogo de ações conhecidas. Tudo que não está aqui cai no _DEFAULT_SPEC.
ACTION_CATALOG: dict[str, ActionSpec] = {
    # leitura / consulta
    "read": ActionSpec("read", False, ActionRisk.LOW),
    "status": ActionSpec("read", False, ActionRisk.LOW),
    "list": ActionSpec("read", False, ActionRisk.LOW),
    "audit_verify": ActionSpec("audit", False, ActionRisk.LOW),
    "audit_export": ActionSpec("audit", False, ActionRisk.LOW),
    # defesa (capacidade core — sem toggle; auditada e com travas de segurança)
    "block_ip": ActionSpec("defense.block_ip", True, ActionRisk.MEDIUM),
    "unblock_ip": ActionSpec("defense.unblock_ip", True, ActionRisk.MEDIUM),
    "isolate_ip": ActionSpec("defense.block_ip", True, ActionRisk.MEDIUM),
    "honeypot_start": ActionSpec("defense.honeypot", True, ActionRisk.MEDIUM),
    "honeypot_stop": ActionSpec("defense.honeypot", True, ActionRisk.MEDIUM),
    # operação NOC
    "block_subscriber": ActionSpec("noc.block_subscriber", True, ActionRisk.MEDIUM),
    "unblock_subscriber": ActionSpec("noc.unblock_subscriber", True, ActionRisk.MEDIUM),
    "run_billing_cycle": ActionSpec("noc.billing", True, ActionRisk.HIGH),
    "device_check": ActionSpec("noc.device_check", False, ActionRisk.LOW),
    # investigação (read-only / allowlist)
    "ssh_command": ActionSpec("investigate.ssh", False, ActionRisk.MEDIUM),
    # infraestrutura de alto impacto — toggle + aprovação
    "mikrotik_write": ActionSpec("infra.mikrotik_write", True, ActionRisk.HIGH, requires_approval=True),
    "asn_block": ActionSpec("infra.asn_block", True, ActionRisk.CRITICAL, "ALLOW_ASN_BLOCK", True),
    "bgp_flowspec": ActionSpec("infra.bgp", True, ActionRisk.CRITICAL, requires_approval=True),
    "brbos_block_domain": ActionSpec("infra.brbos_block", True, ActionRisk.HIGH, "ALLOW_BRBOS_BLOCK", True),
    # exploração ativa — toggle ALLOW_ACTIVE_EXPLOITATION + aprovação
    "run_exploit": ActionSpec("offense.exploit", True, ActionRisk.CRITICAL, "ALLOW_ACTIVE_EXPLOITATION", True),
    "brute_force": ActionSpec("offense.bruteforce", True, ActionRisk.CRITICAL, "ALLOW_ACTIVE_EXPLOITATION", True),
    "run_sqlmap": ActionSpec("offense.sqlmap", True, ActionRisk.CRITICAL, "ALLOW_ACTIVE_EXPLOITATION", True),
    # engenharia social — toggle + engagement_reference (só GERA texto)
    "social_engineering": ActionSpec(
        "social.generate", False, ActionRisk.HIGH, "ALLOW_SOCIAL_ENGINEERING",
        needs_engagement_ref=True,
    ),
}

# Ação desconhecida: conservadora, mas compatível (não exige permissão própria).
_DEFAULT_SPEC = ActionSpec("", True, ActionRisk.MEDIUM)


def _spec(action_type: str) -> ActionSpec:
    return ACTION_CATALOG.get((action_type or "").strip(), _DEFAULT_SPEC)


def _needs_approval(spec: ActionSpec) -> bool:
    return spec.requires_approval or spec.risk in (ActionRisk.HIGH, ActionRisk.CRITICAL)


def evaluate(request) -> ActionDecision:
    """Avalia um ActionRequest e devolve um ActionDecision determinístico."""
    spec = _spec(request.action_type)
    role = rbac.normalize_role(request.role or rbac.default_role())
    mode = (request.environment or operating_mode.get_operating_mode()).strip().lower()

    def decision(d: Decision, reason: str, asset_id=None, target_note="") -> ActionDecision:
        return ActionDecision(
            decision=d, risk=spec.risk, reason=reason,
            required_permission=spec.required_permission, changes_state=spec.changes_state,
            mode=mode, asset_id=asset_id, target_note=target_note,
        )

    # 1) RBAC — papel sem permissão exigida.
    if not rbac.has_permission(role, spec.required_permission):
        return decision(
            Decision.DENY,
            f"papel '{role}' não tem a permissão '{spec.required_permission}' exigida por "
            f"'{request.action_type}'.",
        )

    # 2/5) Inventário + travas de segurança duras.
    tc = asset_registry.check_target(
        request.target, request.action_type, changes_state=spec.changes_state
    )
    if tc.hard_denied:
        return decision(Decision.DENY, f"trava de segurança: {tc.reason}.", target_note=tc.reason)

    # 3) Toggle de capacidade.
    if spec.requires_toggle and not getattr(config, spec.requires_toggle, False):
        return decision(
            Decision.DENY,
            f"capacidade desligada: defina {spec.requires_toggle}=true no .env para habilitar "
            f"'{request.action_type}' (mesmo assim passa por aprovação).",
        )

    # 4) Engenharia social exige referência de engajamento.
    if spec.needs_engagement_ref and not (request.engagement_reference or "").strip():
        return decision(
            Decision.DENY,
            "engenharia social exige 'engagement_reference' (autorização do engajamento) — ausente.",
        )

    # 5) Alvo não autorizado (modo estrito, ou trava lógica do inventário).
    if not tc.authorized:
        return decision(Decision.DENY, f"alvo não autorizado: {tc.reason}.", target_note=tc.reason)

    # 6) Modo operacional: lab/replay não executa ação real que altera estado.
    if spec.changes_state and mode != "real":
        return decision(
            Decision.DRY_RUN_ONLY,
            f"modo operacional '{mode}': ação que altera estado real não executa (só dry-run).",
            asset_id=tc.asset_id, target_note=tc.reason,
        )

    # 7) Aprovação humana para risco alto/crítico (ou marcado).
    if _needs_approval(spec):
        return decision(
            Decision.REQUIRE_APPROVAL,
            f"ação de risco {spec.risk.value} exige aprovação humana fora de banda.",
            asset_id=tc.asset_id, target_note=tc.reason,
        )

    # 8) Permitida.
    return decision(
        Decision.ALLOW,
        f"permitida para papel '{role}' (risco {spec.risk.value}).",
        asset_id=tc.asset_id, target_note=tc.reason,
    )


def runtime_precheck(request) -> ActionDecision:
    """Overlay de governança em RUNTIME para ações que JÁ passam pelo gate de
    aprovação (tools/risk.py) e que JÁ checam seus próprios toggles/guards.

    Aplica só três dimensões — RBAC, trava de segurança dura do inventário e modo
    operacional — e NÃO reavalia toggle/engagement/inventário estrito (a tool já
    cuidou disso). Isso evita divergência de fonte (ex.: toggle mockado no módulo
    da tool vs. config) e mantém compatibilidade: em modo real com papel admin, o
    resultado é sempre ALLOW. Retorna DENY / DRY_RUN_ONLY / ALLOW.
    """
    spec = _spec(request.action_type)
    role = rbac.normalize_role(request.role or rbac.default_role())
    mode = (request.environment or operating_mode.get_operating_mode()).strip().lower()

    def d(dec: Decision, reason: str) -> ActionDecision:
        return ActionDecision(
            decision=dec, risk=spec.risk, reason=reason,
            required_permission=spec.required_permission, changes_state=spec.changes_state, mode=mode,
        )

    if not rbac.has_permission(role, spec.required_permission):
        return d(Decision.DENY, f"papel '{role}' não tem a permissão '{spec.required_permission}'.")
    tc = asset_registry.check_target(request.target, request.action_type, changes_state=spec.changes_state)
    if tc.hard_denied:
        return d(Decision.DENY, f"trava de segurança: {tc.reason}.")
    if spec.changes_state and mode != "real":
        return d(Decision.DRY_RUN_ONLY,
                 f"modo operacional '{mode}': ação que altera estado real não executa (dry-run).")
    return d(Decision.ALLOW, "overlay de governança em runtime: ok")
