"""Modelos compartilhados do Control Plane (módulo folha — sem dependências de
outros módulos de core, para evitar import cíclico entre policy_engine e
control_plane). Os nomes pedidos (ActionRequest/ActionDecision/ActionResult/
ActionRisk/ActionStatus) são reexportados por core.control_plane.
"""

from dataclasses import dataclass, field
from enum import Enum


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    DRY_RUN_ONLY = "dry_run_only"


class ActionRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionStatus(str, Enum):
    EVALUATED = "evaluated"
    ALLOWED = "allowed"
    DENIED = "denied"
    AWAITING_APPROVAL = "awaiting_approval"
    DRY_RUN = "dry_run"
    EXECUTED = "executed"
    FAILED = "failed"


@dataclass
class ActionRequest:
    """Pedido estruturado de ação que entra no Control Plane."""
    action_type: str
    target: str = ""
    actor: str = ""
    role: str = ""
    params: dict = field(default_factory=dict)
    environment: str = ""             # opcional; se vazio, usa o modo do backend
    engagement_reference: str = ""    # exigido p/ engenharia social
    reason: str = ""


@dataclass
class ActionDecision:
    """Resultado determinístico da policy engine."""
    decision: Decision
    risk: ActionRisk
    reason: str
    required_permission: str = ""
    changes_state: bool = True
    mode: str = "real"
    asset_id: str | None = None
    target_note: str = ""


@dataclass
class ActionResult:
    """Resultado final, depois de auditar e (se permitido) executar."""
    status: ActionStatus
    decision: ActionDecision
    output: str = ""
    pending_action_id: int | None = None
