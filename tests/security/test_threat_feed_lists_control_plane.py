"""CP-SD Fase 6M — tools/threat_feed_lists.py:refresh_all_feeds governado
pelo Control Plane antes de baixar as listas públicas de threat feed
(Spamhaus DROP/Feodo Tracker/Emerging Threats) e substituir o cache local.

Achado da Fase 6L (scoping): o refresh não é leitura neutra — a tabela
`threat_feed_entries` que ele substitui alimenta o auto-bloqueio de
firewall dentro de `monitor_loop` (main.py). action_type novo
"threat_feed.refresh_lists" (changes_state=True, MEDIUM, sem aprovação):
RBAC nega sem tocar rede; lab/replay vira DRY_RUN_ONLY (nunca chama
requests.get, nunca substitui o cache). `refresh_feed` (uma fonte só) e
`check_ip_against_feeds`/`describe_ip_feed_check` (leitura pura do cache já
baixado) continuam sem gate — não são os call-sites de bypass da Fase 6L.

Nenhuma rede real: `requests.get` é sempre trocado por um fake local; o
backstop autouse de tests/security/conftest.py também bloqueia
`requests.post`/`get` reais, então mesmo um bug que escapasse do fake seria
pego. DB sempre temporário (fixture autouse `clean_db`, sem
importlib.reload — diferente do padrão antigo de
tests/test_threat_feed_lists.py).

Esta fase NÃO fecha o bypass de `monitor_loop`'s `firewall.block_ip`
direto (que CONSOME o cache atualizado aqui) — isso fica para uma fase
própria (ver teste estático ao final deste arquivo).
"""

import inspect

import pytest

import database.db as db_module
from core import control_plane as cp
from core import rbac
from tools import threat_feed_lists as feeds


def _cp_decision_events() -> list[str]:
    """Linhas de auditoria que só existem se o Control Plane foi
    efetivamente consultado — ausência delas prova que nenhum ActionRequest
    foi montado."""
    with db_module.get_conn() as conn:
        rows = conn.execute(
            "SELECT detail FROM events WHERE event_type IN "
            "('control_plane_decision', 'control_plane_executed')"
        ).fetchall()
    return [r[0] for r in rows]


class _FakeResp:
    text = "203.0.113.0/24 ; SBL1\n198.51.100.5\n"

    def raise_for_status(self):
        pass


@pytest.fixture
def fake_get(monkeypatch):
    """Substitui requests.get por um fake que nunca toca rede.
    `state["count"]` conta quantas vezes foi chamado (1 por fonte)."""
    state = {"count": 0}

    def fake(url, **kw):
        state["count"] += 1
        return _FakeResp()

    monkeypatch.setattr(feeds.requests, "get", fake)
    return state


def _entries_count() -> int:
    return len(db_module.get_all_feed_entries())


# ------------------------- 1: sem Principal -> service:threat-feed, ALLOW -------------------------

def test_refresh_without_context_principal_uses_service_threat_feed(fake_get):
    assert cp.get_current_principal() is None

    result = feeds.refresh_all_feeds()

    assert "atualizado" in result
    assert fake_get["count"] == 3  # 3 fontes
    assert _entries_count() > 0
    blob = " ".join(_cp_decision_events())
    assert "action=threat_feed.refresh_lists" in blob
    assert "actor=service:threat-feed" in blob
    assert "role=service" in blob


# ------------------------- 2: Principal real preservado -------------------------

def test_refresh_inside_real_principal_context_preserves_identity(fake_get):
    real_principal = rbac.Principal("integration:audit-exporter", "service")

    with cp.principal_context(real_principal):
        result = feeds.refresh_all_feeds()

    assert "atualizado" in result
    assert fake_get["count"] == 3
    blob = " ".join(_cp_decision_events())
    assert "actor=integration:audit-exporter" in blob
    assert "role=service" in blob
    assert "actor=service:threat-feed" not in blob


# ------------------------- 3: readonly nega, sem tocar rede -------------------------

def test_refresh_inside_readonly_context_denies_without_network(fake_get):
    readonly_principal = rbac.Principal("user:bob", "readonly")
    entries_before = _entries_count()

    with cp.principal_context(readonly_principal):
        result = feeds.refresh_all_feeds()

    assert "NEGADA" in result
    assert fake_get["count"] == 0
    assert _entries_count() == entries_before
    blob = " ".join(_cp_decision_events())
    assert "action=threat_feed.refresh_lists" in blob
    assert "actor=user:bob" in blob
    assert "role=readonly" in blob
    assert "decision=deny" in blob


# ------------------------- 4/5: lab/replay -> DRY_RUN_ONLY, nunca chama rede -------------------------

def test_refresh_lab_mode_is_dry_run_no_network(fake_get):
    from core import operating_mode

    operating_mode.set_operating_mode("lab")
    entries_before = _entries_count()

    result = feeds.refresh_all_feeds()

    assert "DRY-RUN" in result
    assert fake_get["count"] == 0
    assert _entries_count() == entries_before


def test_refresh_replay_mode_is_dry_run_no_network(fake_get):
    from core import operating_mode

    operating_mode.set_operating_mode("replay")
    entries_before = _entries_count()

    result = feeds.refresh_all_feeds()

    assert "DRY-RUN" in result
    assert fake_get["count"] == 0
    assert _entries_count() == entries_before


# ------------------------- 6: tool do agente protegida indiretamente -------------------------

def test_agent_refresh_threat_feed_lists_under_readonly_context_does_not_escalate(fake_get):
    """Reproduz o padrão da Fase 6D/6H: a tool do agente
    `refresh_threat_feed_lists` chama tools.threat_feed_lists.refresh_all_feeds
    DIRETO, sem gate próprio. Como o ContextVar já carrega a identidade real
    durante a invocação do agente (ask_agent), a chamada interna NÃO pode se
    elevar para service:threat-feed."""
    import agents.nexus_agent as agent_module

    readonly_principal = rbac.Principal("chat:readonly-user", "readonly")

    with cp.principal_context(readonly_principal):
        result = agent_module.refresh_threat_feed_lists.func()

    assert fake_get["count"] == 0
    assert "NEGADA" in result
    blob = " ".join(_cp_decision_events())
    assert "actor=service:threat-feed" not in blob


# ------------------------- 7: check_ip_against_feeds continua leitura pura -------------------------

def test_check_ip_against_feeds_remains_pure_read_no_cp():
    result = feeds.check_ip_against_feeds("8.8.8.8")

    assert result == []
    assert _cp_decision_events() == []


def test_agent_check_ip_against_threat_feed_lists_remains_pure_read_no_cp():
    import agents.nexus_agent as agent_module

    result = agent_module.check_ip_against_threat_feed_lists.func("8.8.8.8")

    assert "não encontrado" in result
    assert _cp_decision_events() == []


# ------------------------- 8: ActionSpec threat_feed.refresh_lists -------------------------

def test_action_spec_threat_feed_refresh_lists():
    from core.policy_engine import ACTION_CATALOG

    spec = ACTION_CATALOG["threat_feed.refresh_lists"]
    assert spec.required_permission == "threat_feed.refresh_lists"
    assert spec.changes_state is True
    assert spec.risk is cp.ActionRisk.MEDIUM
    assert spec.requires_approval is False


# ------------------------- 9/10: RBAC do papel "service" -------------------------

def test_service_role_gained_threat_feed_refresh_lists_permission():
    perms = rbac.ROLE_PERMISSIONS["service"]
    assert "threat_feed.refresh_lists" in perms
    assert "threat_feed.*" not in perms
    assert "threat_feeds.*" not in perms
    assert "reputation.*" not in perms
    assert "*" not in perms


def test_service_role_did_not_become_admin():
    assert rbac.ROLE_PERMISSIONS["service"] != rbac.ROLE_PERMISSIONS["admin"]
    assert "admin" not in rbac.ROLE_PERMISSIONS["service"]


# ------------------------- 11: SERVICE_THREAT_FEED_PRINCIPAL -------------------------

def test_service_threat_feed_principal_role_is_service_not_admin():
    assert rbac.SERVICE_THREAT_FEED_PRINCIPAL.role == "service"
    assert rbac.SERVICE_THREAT_FEED_PRINCIPAL.role != "admin"
    assert rbac.SERVICE_THREAT_FEED_PRINCIPAL.actor == "service:threat-feed"


# ------------------------- 12: papéis humanos inalterados por esta fase -------------------------

def test_human_roles_unchanged_by_this_phase():
    assert rbac.ROLE_PERMISSIONS["admin"] == {"*"}
    assert rbac.ROLE_PERMISSIONS["soc_analyst"] == {"read", "audit", "defense.*", "investigate.*"}
    assert rbac.ROLE_PERMISSIONS["noc_operator"] == {
        "read", "noc.*", "defense.block_ip", "defense.unblock_ip",
        "billing.run_cycle.trigger",
    }
    assert rbac.ROLE_PERMISSIONS["auditor"] == {"read", "audit"}
    assert rbac.ROLE_PERMISSIONS["readonly"] == {"read"}


def test_service_role_full_permission_set_after_phase_6m():
    """Conjunto EXATO e atual de 'service' — autoritativo a partir da Fase
    6M. Testes de fases anteriores (6H/6K) que afirmavam um conjunto exato
    foram convertidos para subconjunto (obsolescência esperada, mesmo
    padrão repetido em toda fase que acrescenta permissão a 'service')."""
    assert rbac.ROLE_PERMISSIONS["service"] == {
        "read",
        "risk.sweep_expired", "audit.checkpoint", "watchdog.check_health", "report.generate",
        "noc.block_subscriber", "noc.unblock_subscriber",
        "billing.run_cycle.trigger",
        "siem.forward_events",
        "threat_feed.refresh_lists",
    }


# ------------------------- 16: gatear o refresh NÃO fecha o bypass do monitor_loop -------------------------

def test_monitor_loop_firewall_block_ip_still_direct_and_unpatched():
    """Teste estático/documentado (não altera main.py): prova que
    monitor_loop continua chamando firewall.block_ip DIRETO, consumindo o
    cache que refresh_all_feeds atualiza — a Fase 6M gateia só a
    ATUALIZAÇÃO do cache, não o CONSUMO dele. Fecha esse bypass fica para
    uma fase própria (ver docs/SESSION-HANDOFF.md)."""
    import main as main_module

    source = inspect.getsource(main_module.monitor_loop)
    assert "check_ip_against_feeds" in source
    assert "firewall.block_ip(ip, reason)" in source
    assert "cp.request_action" not in source
    assert "principal_context" not in source
