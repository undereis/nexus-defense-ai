"""CP-SD Fase 6H — tools/siem.py:forward_new_events governado pelo Control
Plane antes de enviar eventos para um SIEM externo.

Achado da Fase 6G (scoping): `siem.py` não tinha cinto de modo nem RBAC
algum — o Control Plane é a ÚNICA linha de defesa possível aqui (diferente
do billing, que já tinha proteções próprias). action_type novo
"siem.forward_events" (changes_state=True, MEDIUM, sem aprovação): RBAC nega
sem tocar rede; lab/replay vira DRY_RUN_ONLY (nunca chama requests.post).
`is_enabled()`/modo inválido/"nada novo para enviar" continuam resolvidos
ANTES do Control Plane, sem criar ActionRequest à toa.

Nenhuma rede real: `_SENDERS["webhook"]` é sempre trocado por um fake
(`fake_sender`); o backstop autouse de tests/security/conftest.py também
bloqueia `requests.post`/`get` reais, então mesmo um bug que escapasse do
fake seria pego. DB sempre temporário (fixture autouse `clean_db`).
"""

import pytest
import requests

import database.db as db_module
from core import control_plane as cp
from core import operating_mode, rbac
from tools import siem


def _seed_events(n: int = 1) -> None:
    for i in range(n):
        db_module.log_event(f"test_event_{i}", None, f"detail {i}")


def _cp_decision_events() -> list[str]:
    """Linhas de auditoria que só existem se o Control Plane foi
    efetivamente consultado — ausência delas prova que nenhum ActionRequest
    foi montado (caso de SIEM desligado / nada novo para enviar)."""
    with db_module.get_conn() as conn:
        rows = conn.execute(
            "SELECT detail FROM events WHERE event_type IN "
            "('control_plane_decision', 'control_plane_executed')"
        ).fetchall()
    return [r[0] for r in rows]


def _event_types() -> list[str]:
    with db_module.get_conn() as conn:
        return [r[0] for r in conn.execute("SELECT event_type FROM events").fetchall()]


def _siem_enable(monkeypatch) -> None:
    monkeypatch.setattr(siem, "SIEM_MODE", "webhook")
    monkeypatch.setattr(siem, "SIEM_URL", "https://siem.example.test/ingest")


@pytest.fixture
def fake_sender(monkeypatch):
    """Liga o SIEM (modo webhook) e troca o sender real por um fake que
    nunca toca rede. `state["ok"]` controla o resultado simulado do envio."""
    _siem_enable(monkeypatch)
    state = {"docs": None, "count": 0, "ok": True}

    def fake(docs):
        state["docs"] = docs
        state["count"] += 1
        return state["ok"]

    monkeypatch.setitem(siem._SENDERS, "webhook", fake)
    return state


# ------------------------- 1/2: identidade do envio (sem Principal vs. real) -------------------------

def test_forward_without_context_principal_uses_service_siem(fake_sender):
    """Caso do siem_loop automático: sem Principal no ContextVar, o envio
    real usa SERVICE_SIEM_PRINCIPAL (service:siem), ALLOW, cursor avança."""
    assert cp.get_current_principal() is None
    _seed_events(2)
    cursor_before = db_module.get_siem_cursor()

    result = siem.forward_new_events()

    assert fake_sender["count"] == 1
    assert "evento(s) enviados" in result
    assert db_module.get_siem_cursor() > cursor_before
    blob = " ".join(_cp_decision_events())
    assert "action=siem.forward_events" in blob
    assert "actor=service:siem" in blob
    assert "role=service" in blob


def test_forward_inside_real_principal_context_preserves_identity(fake_sender):
    """Com um Principal real já no contexto, forward_new_events NÃO pode
    sobrescrevê-lo para service:siem — mesmo que o papel seja "service"
    (que já tem a permissão), o ACTOR real deve aparecer na auditoria."""
    real_principal = rbac.Principal("integration:audit-exporter", "service")
    _seed_events(2)
    cursor_before = db_module.get_siem_cursor()

    with cp.principal_context(real_principal):
        siem.forward_new_events()

    assert fake_sender["count"] == 1
    assert db_module.get_siem_cursor() > cursor_before
    blob = " ".join(_cp_decision_events())
    assert "actor=integration:audit-exporter" in blob
    assert "role=service" in blob
    assert "actor=service:siem" not in blob


# ------------------------- 3: readonly nega, sem tocar rede -------------------------

def test_forward_inside_readonly_context_denies_without_network(fake_sender):
    _seed_events(2)
    readonly_principal = rbac.Principal("user:bob", "readonly")
    cursor_before = db_module.get_siem_cursor()

    with cp.principal_context(readonly_principal):
        result = siem.forward_new_events()

    assert "NEGADO" in result
    assert fake_sender["count"] == 0
    assert db_module.get_siem_cursor() == cursor_before
    blob = " ".join(_cp_decision_events())
    assert "action=siem.forward_events" in blob
    assert "actor=user:bob" in blob
    assert "role=readonly" in blob
    assert "decision=deny" in blob


# ------------------------- 4/5: lab/replay -> DRY_RUN_ONLY, nunca chama rede -------------------------

def test_forward_lab_mode_is_dry_run_no_network(fake_sender):
    _seed_events(2)
    operating_mode.set_operating_mode("lab")
    cursor_before = db_module.get_siem_cursor()

    result = siem.forward_new_events()

    assert "DRY-RUN" in result
    assert fake_sender["count"] == 0
    assert db_module.get_siem_cursor() == cursor_before


def test_forward_replay_mode_is_dry_run_no_network(fake_sender):
    _seed_events(2)
    operating_mode.set_operating_mode("replay")
    cursor_before = db_module.get_siem_cursor()

    result = siem.forward_new_events()

    assert "DRY-RUN" in result
    assert fake_sender["count"] == 0
    assert db_module.get_siem_cursor() == cursor_before


# ------------------------- 6: SIEM desabilitado -> comportamento anterior, sem CP -------------------------

def test_forward_disabled_preserves_old_behavior_no_cp_call():
    assert not siem.is_enabled()

    result = siem.forward_new_events()

    assert "SIEM desligado" in result
    assert _cp_decision_events() == []  # nenhum ActionRequest foi montado


# ------------------------- 7: sem eventos novos -> comportamento anterior, sem CP -------------------------

def test_forward_no_new_events_preserves_old_behavior_no_cp_call(fake_sender):
    result = siem.forward_new_events()

    assert "nada novo" in result
    assert fake_sender["count"] == 0
    assert _cp_decision_events() == []  # nenhum ActionRequest foi montado


# ------------------------- 8: erro do sender -> cursor mantido, log preservado -------------------------

def test_forward_sender_raises_error_cursor_not_advanced(fake_sender, monkeypatch):
    _seed_events(1)
    cursor_before = db_module.get_siem_cursor()

    def raising_sender(docs):
        raise requests.RequestException("boom")

    monkeypatch.setitem(siem._SENDERS, "webhook", raising_sender)

    result = siem.forward_new_events()

    assert "falha ao enviar" in result
    assert db_module.get_siem_cursor() == cursor_before
    assert "siem_forward_error" in _event_types()
    # o CP registrou a tentativa (ALLOW + executado) — a exceção foi tratada
    # DENTRO do executor, não propagada ao request_action.
    blob = " ".join(_cp_decision_events())
    assert "action=siem.forward_events" in blob
    assert "decision=allow" in blob


# ------------------------- 9: destino recusa (ok=False) -> cursor mantido -------------------------

def test_forward_sender_returns_false_cursor_not_advanced(fake_sender):
    _seed_events(1)
    fake_sender["ok"] = False
    cursor_before = db_module.get_siem_cursor()

    result = siem.forward_new_events()

    assert "recusou" in result
    assert fake_sender["count"] == 1
    assert db_module.get_siem_cursor() == cursor_before
    assert "siem_forward_error" in _event_types()


# ------------------------- 10: tool do agente protegida indiretamente -------------------------

def test_agent_siem_forward_now_under_readonly_context_does_not_escalate(fake_sender):
    """Reproduz o padrão da Fase 6D: a tool do agente `siem_forward_now`
    chama tools.siem.forward_new_events DIRETO, sem gate próprio. Como o
    ContextVar já carrega a identidade real durante a invocação do agente
    (ask_agent), a chamada interna NÃO pode se elevar para service:siem."""
    import agents.nexus_agent as agent_module

    _seed_events(1)
    readonly_principal = rbac.Principal("chat:readonly-user", "readonly")

    with cp.principal_context(readonly_principal):
        result = agent_module.siem_forward_now.func()

    assert fake_sender["count"] == 0
    assert "NEGADO" in result
    blob = " ".join(_cp_decision_events())
    assert "actor=service:siem" not in blob


def test_agent_siem_status_remains_pure_read_no_cp():
    """siem_status/describe_status continuam leitura pura, sem CP nesta
    fase — não deve gerar nenhum evento de decisão do Control Plane."""
    import agents.nexus_agent as agent_module

    result = agent_module.siem_status.func()

    assert "SIEM" in result
    assert _cp_decision_events() == []


# ------------------------- 11/12: RBAC do papel "service" -------------------------

def test_service_role_gained_only_siem_forward_events_permission():
    perms = rbac.ROLE_PERMISSIONS["service"]
    assert "siem.forward_events" in perms
    assert "siem.*" not in perms
    assert "*" not in perms


def test_service_siem_principal_role_is_service_not_admin():
    assert rbac.SERVICE_SIEM_PRINCIPAL.role == "service"
    assert rbac.SERVICE_SIEM_PRINCIPAL.role != "admin"
    assert rbac.SERVICE_SIEM_PRINCIPAL.actor == "service:siem"


# ------------------------- 13: papéis humanos inalterados por esta fase -------------------------

def test_human_roles_unchanged_by_this_phase():
    assert rbac.ROLE_PERMISSIONS["admin"] == {"*"}
    assert rbac.ROLE_PERMISSIONS["soc_analyst"] == {"read", "audit", "defense.*", "investigate.*"}
    assert rbac.ROLE_PERMISSIONS["noc_operator"] == {
        "read", "noc.*", "defense.block_ip", "defense.unblock_ip",
        "billing.run_cycle.trigger",
    }
    assert rbac.ROLE_PERMISSIONS["auditor"] == {"read", "audit"}
    assert rbac.ROLE_PERMISSIONS["readonly"] == {"read"}


def test_service_role_permissions_after_phase_6h_are_subset():
    """CP-SD Fase 6M (posterior a esta) acrescentou mais 1 permissão
    ("threat_feed.refresh_lists") — a checagem do papel "service" é por
    SUBCONJUNTO (não "=="): o conjunto EXATO e atualizado vive em
    tests/security/test_threat_feed_lists_control_plane.py::test_service_role_full_permission_set_after_phase_6m."""
    assert {
        "read",
        "risk.sweep_expired", "audit.checkpoint", "watchdog.check_health", "report.generate",
        "noc.block_subscriber", "noc.unblock_subscriber",
        "billing.run_cycle.trigger",
        "siem.forward_events",
    }.issubset(rbac.ROLE_PERMISSIONS["service"])


# ------------------------- 14: ActionSpec siem.forward_events -------------------------

def test_action_spec_siem_forward_events():
    from core.policy_engine import ACTION_CATALOG

    spec = ACTION_CATALOG["siem.forward_events"]
    assert spec.required_permission == "siem.forward_events"
    assert spec.changes_state is True
    assert spec.risk is cp.ActionRisk.MEDIUM
    assert spec.requires_approval is False


# =====================================================================
# CP-SD Fase 6K — cooldown de reavaliação em DENY/DRY_RUN_ONLY
#
# Achado da 6I/6J: o Control Plane reauditava a MESMA decisão DENY/
# DRY_RUN_ONLY a cada ciclo do siem_loop, gravando 1 `control_plane_decision`
# novo por ciclo pra sempre (cursor nunca avança, lote real fica preso atrás
# do próprio ruído do CP). O cooldown (`siem_state.last_blocked_*`,
# `SIEM_REAUDIT_COOLDOWN_SECONDS`) pula a reavaliação enquanto a MESMA
# combinação action_type/decisão/modo/actor/role continuar bloqueada.
# =====================================================================

def _blocked_decisions_count() -> int:
    return len(_cp_decision_events())


# ------------------------- DB layer: get/set/clear_siem_blocked_state -------------------------

def test_siem_blocked_state_db_roundtrip():
    assert db_module.get_siem_blocked_state() is None

    db_module.set_siem_blocked_state(
        "siem.forward_events", "denied", "real", "user:x", "readonly", "2026-01-01 00:00:00",
    )
    state = db_module.get_siem_blocked_state()
    assert state == {
        "action_type": "siem.forward_events", "decision": "denied", "mode": "real",
        "actor": "user:x", "role": "readonly", "blocked_at": "2026-01-01 00:00:00",
    }

    db_module.clear_siem_blocked_state()
    assert db_module.get_siem_blocked_state() is None


def test_siem_blocked_state_does_not_clobber_cursor():
    """set/clear_siem_blocked_state NUNCA mexem em last_event_id (cursor)."""
    db_module.set_siem_cursor(42)

    db_module.set_siem_blocked_state(
        "siem.forward_events", "dry_run", "lab", "service:siem", "service", "2026-01-01 00:00:00",
    )
    assert db_module.get_siem_cursor() == 42

    db_module.clear_siem_blocked_state()
    assert db_module.get_siem_cursor() == 42


# ------------------------- 1: DENY cria blocked_state -------------------------

def test_deny_creates_blocked_state(fake_sender):
    _seed_events(2)
    readonly_principal = rbac.Principal("user:bob", "readonly")

    with cp.principal_context(readonly_principal):
        result = siem.forward_new_events()

    assert "NEGADO" in result
    assert fake_sender["count"] == 0
    blocked = db_module.get_siem_blocked_state()
    assert blocked is not None
    assert blocked["action_type"] == "siem.forward_events"
    assert blocked["decision"] == cp.ActionStatus.DENIED.value
    assert blocked["mode"] == "real"
    assert blocked["actor"] == "user:bob"
    assert blocked["role"] == "readonly"


# ------------------------- 2: 2ª chamada DENY dentro do cooldown -------------------------

def test_deny_second_call_within_cooldown_skips_control_plane(fake_sender):
    _seed_events(2)
    readonly_principal = rbac.Principal("user:bob", "readonly")
    cursor_before = db_module.get_siem_cursor()

    with cp.principal_context(readonly_principal):
        first = siem.forward_new_events()
        decisions_after_first = _blocked_decisions_count()
        second = siem.forward_new_events()

    assert "NEGADO" in first
    assert "cooldown" in second.lower()
    assert "bloqueado" in second.lower()
    assert _blocked_decisions_count() == decisions_after_first  # nenhum evento novo
    assert fake_sender["count"] == 0
    assert db_module.get_siem_cursor() == cursor_before


# ------------------------- 3: DENY com cooldown expirado -------------------------

def test_deny_reaudits_after_cooldown_expires(fake_sender, monkeypatch):
    _seed_events(2)
    readonly_principal = rbac.Principal("user:bob", "readonly")

    with cp.principal_context(readonly_principal):
        siem.forward_new_events()
        decisions_after_first = _blocked_decisions_count()

    monkeypatch.setattr(siem, "SIEM_REAUDIT_COOLDOWN_SECONDS", 0)

    with cp.principal_context(readonly_principal):
        second = siem.forward_new_events()

    assert "NEGADO" in second
    assert _blocked_decisions_count() > decisions_after_first
    blocked = db_module.get_siem_blocked_state()
    assert blocked is not None
    assert blocked["decision"] == cp.ActionStatus.DENIED.value


# ------------------------- 4: DRY_RUN_ONLY em lab cria blocked_state -------------------------

def test_dry_run_lab_creates_blocked_state(fake_sender):
    _seed_events(2)
    operating_mode.set_operating_mode("lab")

    result = siem.forward_new_events()

    assert "DRY-RUN" in result
    assert fake_sender["count"] == 0
    blocked = db_module.get_siem_blocked_state()
    assert blocked is not None
    assert blocked["decision"] == cp.ActionStatus.DRY_RUN.value
    assert blocked["mode"] == "lab"
    assert blocked["actor"] == rbac.SERVICE_SIEM_PRINCIPAL.actor
    assert blocked["role"] == "service"


# ------------------------- 5: 2ª chamada DRY_RUN dentro do cooldown -------------------------

def test_dry_run_second_call_within_cooldown_skips_control_plane(fake_sender):
    _seed_events(2)
    operating_mode.set_operating_mode("lab")
    cursor_before = db_module.get_siem_cursor()

    first = siem.forward_new_events()
    decisions_after_first = _blocked_decisions_count()
    second = siem.forward_new_events()

    assert "DRY-RUN" in first
    assert "cooldown" in second.lower()
    assert _blocked_decisions_count() == decisions_after_first
    assert fake_sender["count"] == 0
    assert db_module.get_siem_cursor() == cursor_before


# ------------------------- 6: mudança de modo invalida cooldown -------------------------

def test_mode_change_invalidates_cooldown(fake_sender):
    _seed_events(2)
    operating_mode.set_operating_mode("lab")
    siem.forward_new_events()  # DRY_RUN_ONLY, registra blocked_state em lab
    assert db_module.get_siem_blocked_state() is not None

    operating_mode.set_operating_mode("real")
    result = siem.forward_new_events()

    assert fake_sender["count"] == 1
    assert "evento(s) enviados" in result
    assert db_module.get_siem_blocked_state() is None


# ------------------------- 7: mudança de actor/role invalida cooldown -------------------------

def test_actor_role_change_invalidates_cooldown(fake_sender):
    _seed_events(2)
    readonly_principal = rbac.Principal("user:bob", "readonly")

    with cp.principal_context(readonly_principal):
        siem.forward_new_events()  # DENY, blocked_state para user:bob/readonly
    assert db_module.get_siem_blocked_state()["actor"] == "user:bob"

    # Sem Principal no contexto -> cai para SERVICE_SIEM_PRINCIPAL, que TEM a
    # permissão: a decisão de 'bob' não pode ser reaproveitada por outra identidade.
    result = siem.forward_new_events()

    assert fake_sender["count"] == 1
    assert "evento(s) enviados" in result
    assert db_module.get_siem_blocked_state() is None


# ------------------------- 8: ALLOW limpa blocked_state pré-existente -------------------------

def test_allow_clears_preexisting_blocked_state(fake_sender):
    _seed_events(2)
    db_module.set_siem_blocked_state(
        "siem.forward_events", cp.ActionStatus.DENIED.value, "real",
        "user:someone-else", "readonly", "2020-01-01 00:00:00",
    )
    cursor_before = db_module.get_siem_cursor()

    result = siem.forward_new_events()

    assert fake_sender["count"] == 1
    assert "evento(s) enviados" in result
    assert db_module.get_siem_cursor() > cursor_before
    assert db_module.get_siem_blocked_state() is None


# ------------------------- 9: falha de sender não vira blocked_state -------------------------

def test_sender_returns_false_does_not_create_blocked_state(fake_sender):
    _seed_events(1)
    fake_sender["ok"] = False
    cursor_before = db_module.get_siem_cursor()

    result = siem.forward_new_events()

    assert "recusou" in result
    assert db_module.get_siem_cursor() == cursor_before
    assert db_module.get_siem_blocked_state() is None


def test_sender_exception_does_not_create_blocked_state(fake_sender, monkeypatch):
    _seed_events(1)

    def raising_sender(docs):
        raise requests.RequestException("boom")

    monkeypatch.setitem(siem._SENDERS, "webhook", raising_sender)

    result = siem.forward_new_events()

    assert "falha ao enviar" in result
    assert db_module.get_siem_blocked_state() is None


# ------------------------- 10: regressão de starvation -------------------------

def test_starvation_regression_repeated_deny_does_not_grow_events_linearly(fake_sender):
    """Antes da 6K: N chamadas em DENY geravam N `control_plane_decision`
    novos (1 por ciclo, crescimento sem teto — achado da 6J). Depois da 6K:
    só a 1ª chamada audita de verdade; as 19 seguintes (dentro do cooldown)
    são early-return, sem tocar `events`."""
    _seed_events(2)
    readonly_principal = rbac.Principal("user:bob", "readonly")
    cursor_before = db_module.get_siem_cursor()

    with cp.principal_context(readonly_principal):
        for _ in range(20):
            siem.forward_new_events()

    assert fake_sender["count"] == 0
    assert db_module.get_siem_cursor() == cursor_before
    assert _blocked_decisions_count() == 1  # não 20


# ------------------------- 11: cursor preservado em DENY/DRY_RUN/cooldown -------------------------

def test_cursor_never_advances_across_deny_dry_run_and_cooldown(fake_sender):
    _seed_events(2)
    cursor_before = db_module.get_siem_cursor()
    readonly_principal = rbac.Principal("user:bob", "readonly")

    with cp.principal_context(readonly_principal):
        siem.forward_new_events()  # DENY
        siem.forward_new_events()  # cooldown
    assert db_module.get_siem_cursor() == cursor_before

    operating_mode.set_operating_mode("lab")
    siem.forward_new_events()  # DRY_RUN_ONLY
    siem.forward_new_events()  # cooldown
    assert db_module.get_siem_cursor() == cursor_before
    assert fake_sender["count"] == 0


# ------------------------- 12: sem eventos novos não cria blocked_state -------------------------

def test_no_new_events_does_not_create_blocked_state(fake_sender):
    result = siem.forward_new_events()

    assert "nada novo" in result
    assert fake_sender["count"] == 0
    assert db_module.get_siem_blocked_state() is None


# ------------------------- 13: SIEM desabilitado não cria blocked_state -------------------------

def test_disabled_does_not_create_blocked_state():
    assert not siem.is_enabled()

    result = siem.forward_new_events()

    assert "desligado" in result
    assert db_module.get_siem_blocked_state() is None


# ------------------------- 14: ALLOW normal inalterado pela 6K -------------------------

def test_allow_normal_flow_unaffected_by_cooldown_mechanism(fake_sender):
    _seed_events(2)
    cursor_before = db_module.get_siem_cursor()

    result = siem.forward_new_events()

    assert fake_sender["count"] == 1
    assert "evento(s) enviados" in result
    assert db_module.get_siem_cursor() > cursor_before
    assert db_module.get_siem_blocked_state() is None
    blob = " ".join(_cp_decision_events())
    assert "action=siem.forward_events" in blob
    assert "decision=allow" in blob


# ------------------------- 15: early-return de cooldown não grava NENHUM evento -------------------------

def test_cooldown_early_return_creates_no_events_at_all(fake_sender):
    _seed_events(2)
    readonly_principal = rbac.Principal("user:bob", "readonly")

    with cp.principal_context(readonly_principal):
        siem.forward_new_events()
        events_after_first = len(_event_types())
        siem.forward_new_events()
        events_after_second = len(_event_types())

    assert events_after_second == events_after_first
