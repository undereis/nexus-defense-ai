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


def test_service_role_full_permission_set_after_phase_6h():
    assert rbac.ROLE_PERMISSIONS["service"] == {
        "read",
        "risk.sweep_expired", "audit.checkpoint", "watchdog.check_health", "report.generate",
        "noc.block_subscriber", "noc.unblock_subscriber",
        "billing.run_cycle.trigger",
        "siem.forward_events",
    }


# ------------------------- 14: ActionSpec siem.forward_events -------------------------

def test_action_spec_siem_forward_events():
    from core.policy_engine import ACTION_CATALOG

    spec = ACTION_CATALOG["siem.forward_events"]
    assert spec.required_permission == "siem.forward_events"
    assert spec.changes_state is True
    assert spec.risk is cp.ActionRisk.MEDIUM
    assert spec.requires_approval is False
