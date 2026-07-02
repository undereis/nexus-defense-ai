"""Control Plane (Prioridade 1) — porta da frente única para ações sensíveis.

Fluxo (arquitetura pedida):

    Usuário/API/IA → ActionRequest → Control Plane → Policy Engine
      → ativo autorizado → papel/permissão → risco e modo operacional
      → aprovação humana quando necessário → auditoria → executor → resultado auditado

Reaproveita o que já existe e é forte, em vez de duplicar:
  - APROVAÇÃO: tools/risk.py (gate de confirmação fora de banda, rate-limit,
    claim atômico, auditoria) — o Control Plane delega o caminho REQUIRE_APPROVAL
    a ele, registrando o executor por `tool_name` e passando os params como kwargs
    (mesmo padrão das tools de alto risco já existentes).
  - AUDITORIA: database.db.log_event (hash chain), com os params REDIGIDOS
    (core.redaction) — segredo nunca entra na trilha em claro.

Compatibilidade: por padrão (actor local_admin / role admin / modo real) o
comportamento permitido é o mesmo de hoje — a diferença é que agora toda decisão
(allow/deny/approval/dry-run/execute) fica auditada e governada.

Os nomes pedidos são reexportados aqui para quem importar de core.control_plane.
"""

import contextvars
from contextlib import contextmanager

from core import rbac
from core.models import (  # reexport
    ActionDecision,
    ActionRequest,
    ActionResult,
    ActionRisk,
    ActionStatus,
    Decision,
)
from core.policy_engine import evaluate as _policy_evaluate
from core.redaction import redact, redact_kwargs
from database.db import log_event

__all__ = [
    "ActionRequest", "ActionDecision", "ActionResult", "ActionRisk", "ActionStatus",
    "Decision", "evaluate", "request_action", "make_request",
    "get_current_principal", "principal_context",
]


# --- Identidade EFETIVA durante a execução (Fase 2) ---
# ContextVar do Principal ativo. É setado por quem tem a identidade real (ex.:
# api/server -> ask_agent no /chat) e lido por `make_request` para preencher
# actor/role quando não vierem explícitos. ContextVar isola por thread/tarefa
# async — o Principal de uma execução NÃO vaza para outra concorrente. Default
# None = "nenhuma identidade propagada" (caminho direto/CLI decide o fallback).
_current_principal: contextvars.ContextVar = contextvars.ContextVar(
    "nexus_current_principal", default=None
)


def get_current_principal():
    """Principal ativo neste contexto de execução, ou None se nenhum foi setado."""
    return _current_principal.get()


@contextmanager
def principal_context(principal):
    """Seta o Principal ativo enquanto o bloco roda e o RESETA ao sair (mesmo em
    exceção). Use ao redor da execução do agente para propagar a identidade real
    às tools/Control Plane sem passar argumento por todas as 200+ tools."""
    token = _current_principal.set(principal)
    try:
        yield
    finally:
        _current_principal.reset(token)


def make_request(action_type: str, target: str = "", *, actor: str = "", role: str = "",
                 params: dict | None = None, environment: str = "",
                 engagement_reference: str = "", reason: str = "") -> ActionRequest:
    """Monta um ActionRequest resolvendo a identidade nesta ORDEM (Fase 2):

      1. `actor`/`role` explícitos (ex.: rotas REST que já passam o papel do token);
      2. Principal ATIVO no contexto (propagado por `principal_context` — ex.: o
         /chat seta o Principal do token antes de invocar o agente);
      3. fallback `local_admin`/`admin` — só quando NÃO há identidade propagada
         (caminho local/CLI/direto). A API sempre propaga um Principal, então uma
         requisição de API nunca cai neste fallback como admin.
    """
    current = get_current_principal()
    resolved_actor = actor or (current.actor if current else rbac.default_actor())
    resolved_role = role or (current.role if current else rbac.default_role())
    return ActionRequest(
        action_type=action_type,
        target=target or "",
        actor=resolved_actor,
        role=resolved_role,
        params=params or {},
        environment=environment or "",
        engagement_reference=engagement_reference or "",
        reason=reason or "",
    )


def _summary(req: ActionRequest, dec: ActionDecision) -> str:
    tgt = f" alvo={req.target}" if req.target else ""
    return f"{req.action_type}{tgt} (risco {dec.risk.value}, papel {req.role})"


def _audit(event_type: str, req: ActionRequest, dec: ActionDecision, extra: str = "") -> None:
    """Audita uma etapa do Control Plane com params REDIGIDOS."""
    safe_params = redact_kwargs(dict(req.params))
    detail = (
        f"action={req.action_type} actor={req.actor} role={req.role} "
        f"decision={dec.decision.value} risk={dec.risk.value} mode={dec.mode} "
        f"params={safe_params} reason={redact(dec.reason)}"
    )
    if extra:
        detail += f" {redact(extra)}"
    log_event(event_type, req.target or None, detail, action_taken=dec.decision.value)


def evaluate(req: ActionRequest) -> ActionDecision:
    """Avalia a política e AUDITA a decisão (sem executar nada)."""
    dec = _policy_evaluate(req)
    _audit("control_plane_decision", req, dec)
    return dec


def precheck_runtime(req: ActionRequest) -> ActionDecision:
    """Overlay de governança (RBAC + segurança + modo) para ações que já passam
    pelo gate de aprovação de tools/risk.py. Audita e devolve a decisão."""
    from core.policy_engine import runtime_precheck
    dec = runtime_precheck(req)
    _audit("control_plane_precheck", req, dec)
    return dec


def request_action(
    req: ActionRequest,
    executor=None,
    *,
    tool_name: str | None = None,
    dry_run_executor=None,
    approval_ttl_minutes: int = 10,
    kb_query: str = "",
) -> ActionResult:
    """Avalia, audita e — só se permitido — executa.

    - executor(**params)        : roda a ação real (caminho ALLOW).
    - dry_run_executor(**params) : preview read-only (caminho DRY_RUN_ONLY).
    - tool_name                  : nome sob o qual o executor é registrado no
                                   gate de aprovação (default = action_type).
    """
    dec = evaluate(req)
    params = dict(req.params)
    name = tool_name or req.action_type

    # DENY — não executa em hipótese alguma.
    if dec.decision is Decision.DENY:
        return ActionResult(ActionStatus.DENIED, dec, output=f"NEGADO: {dec.reason}")

    # DRY_RUN_ONLY — modo lab/replay: nunca toca o estado real.
    if dec.decision is Decision.DRY_RUN_ONLY:
        if dry_run_executor is not None:
            try:
                out = dry_run_executor(**params)
            except Exception as exc:  # dry-run nunca deve derrubar nada
                out = f"(dry-run falhou: {exc})"
        else:
            out = f"[dry-run] ação '{req.action_type}' não executada no modo '{dec.mode}'."
        return ActionResult(ActionStatus.DRY_RUN, dec, output=redact(out))

    # REQUIRE_APPROVAL — delega ao gate fora de banda (tools/risk.py).
    if dec.decision is Decision.REQUIRE_APPROVAL:
        from tools import risk as risk_gate
        if executor is None:
            return ActionResult(
                ActionStatus.AWAITING_APPROVAL, dec,
                output=("Aprovação humana necessária, mas nenhum executor foi fornecido a este "
                        "caminho. Use a tool específica (já gated) para confirmar."),
            )
        risk_gate.register_action(name, executor)
        text = risk_gate.request_confirmation(
            name, _summary(req, dec), ttl_minutes=approval_ttl_minutes, kb_query=kb_query,
            _skip_policy=True, **params
        )
        return ActionResult(ActionStatus.AWAITING_APPROVAL, dec, output=text)

    # ALLOW — executa e audita o resultado.
    if executor is None:
        return ActionResult(ActionStatus.ALLOWED, dec, output=f"PERMITIDO: {dec.reason}")
    try:
        out = executor(**params)
    except Exception as exc:
        _audit("control_plane_execution_failed", req, dec, extra=f"error={exc!r}")
        return ActionResult(ActionStatus.FAILED, dec, output=f"Execução falhou: {exc}")
    _audit("control_plane_executed", req, dec)
    return ActionResult(ActionStatus.EXECUTED, dec, output=redact(str(out)))
