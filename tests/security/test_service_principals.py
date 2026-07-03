"""CP-SD Fase 5A — Service Principals para jobs automáticos internos.

Prepara o terreno para migrar os loops de main.py (monitor, proactive_audit,
reconcile, billing, playbook, honeypot, honeytoken, watchdog, siem, o reporter
de AbuseIPDB) para usarem uma identidade EXPLÍCITA em vez de caírem no
fallback local_admin/admin do ask_agent. Esta fase NÃO migra main.py — só cria
os Principals, o papel "service" (conservador, igual readonly) e prova que a
propagação via ContextVar/Control Plane já funciona para eles com a
infraestrutura existente (principal_context, make_request, ask_agent).

Sem LLM real (agente stubado), sem firewall/rede/Mikrotik/AbuseIPDB real.
"""

import pytest

from core import control_plane as cp
from core import rbac
from core.models import Decision

ALL_SERVICE_PRINCIPALS = [
    rbac.SERVICE_MONITOR_PRINCIPAL,
    rbac.SERVICE_PROACTIVE_AUDIT_PRINCIPAL,
    rbac.SERVICE_RECONCILE_PRINCIPAL,
    rbac.SERVICE_BILLING_PRINCIPAL,
    rbac.SERVICE_PLAYBOOK_PRINCIPAL,
    rbac.SERVICE_HONEYPOT_PRINCIPAL,
    rbac.SERVICE_HONEYTOKEN_PRINCIPAL,
    rbac.SERVICE_ABUSEIPDB_REPORTER_PRINCIPAL,
    rbac.SERVICE_WATCHDOG_PRINCIPAL,
    rbac.SERVICE_SIEM_PRINCIPAL,
]


# ------------------------- 1: existem e são Principals válidos -------------------------

def test_service_principals_exist_and_are_valid_principals():
    assert len(ALL_SERVICE_PRINCIPALS) == 10
    for p in ALL_SERVICE_PRINCIPALS:
        assert isinstance(p, rbac.Principal)
        assert p.actor.startswith("service:")
        assert p.role in rbac.ROLES


def test_service_principal_factory_builds_expected_principal():
    p = rbac.service_principal("custom-job")
    assert p == rbac.Principal("service:custom-job", "service")


# ------------------------- microcorreção: validação do nome do serviço -------------------------
# name vai para actor -> auditoria/log/hash chain. Nome livre não escala privilégio
# (o papel é sempre "service"), mas pode poluir a trilha ou confundir operação
# (ex.: forjar um actor parecido com "service:admin" ou injetar ':'/quebra de linha).

def test_service_principal_monitor_name_is_valid():
    assert rbac.service_principal("monitor") == rbac.Principal("service:monitor", "service")


def test_service_principal_proactive_audit_name_is_valid():
    assert rbac.service_principal("proactive-audit") == rbac.Principal(
        "service:proactive-audit", "service"
    )


def test_service_principal_abuseipdb_reporter_name_is_valid():
    assert rbac.service_principal("abuseipdb-reporter") == rbac.Principal(
        "service:abuseipdb-reporter", "service"
    )


@pytest.mark.parametrize(
    "bad_name",
    [
        "",
        "../admin",
        "service:admin",
        "local_admin\nrole=admin",
        "-monitor",
        "_monitor",
        "monitor test",
        "monitor/admin",
        "a" * 65,
    ],
)
def test_service_principal_rejects_invalid_names(bad_name):
    with pytest.raises(ValueError):
        rbac.service_principal(bad_name)


def test_service_principal_actors_are_unique():
    actors = [p.actor for p in ALL_SERVICE_PRINCIPALS]
    assert len(actors) == len(set(actors))


# ------------------------- 2/3: nunca admin, nunca "*" -------------------------

def test_service_principals_never_use_admin_role():
    for p in ALL_SERVICE_PRINCIPALS:
        assert p.role != "admin"
        assert p.role == "service"


def test_service_role_never_grants_wildcard():
    perms = rbac.ROLE_PERMISSIONS["service"]
    assert "*" not in perms


def test_service_role_permission_includes_readonly_baseline():
    """Papel "service" começou (Fase 5A) no MESMO nível de "readonly". Fases
    futuras que migrarem cada loop de fato concedem permissão mínima
    ADICIONAL — ver CP-SD Fase 6B (risk.sweep_expired/audit.checkpoint/
    watchdog.check_health/report.generate) em
    test_internal_loops_control_plane.py. O baseline "read" nunca é
    removido; "service" é sempre um superconjunto de "readonly"."""
    assert rbac.ROLE_PERMISSIONS["readonly"].issubset(rbac.ROLE_PERMISSIONS["service"])


# ------------------------- 4/5: principal_context + make_request herdam -------------------------

def test_can_enter_principal_context_with_service_principal():
    assert cp.get_current_principal() is None
    with cp.principal_context(rbac.SERVICE_MONITOR_PRINCIPAL):
        assert cp.get_current_principal() == rbac.SERVICE_MONITOR_PRINCIPAL
    assert cp.get_current_principal() is None  # resetado ao sair


def test_make_request_inherits_service_principal_in_context():
    with cp.principal_context(rbac.SERVICE_RECONCILE_PRINCIPAL):
        req = cp.make_request("block_ip", target="203.0.113.9")
    assert req.actor == "service:reconcile"
    assert req.role == "service"


def test_service_principal_denied_write_action_at_policy_level():
    """Papel "service" só tem "read" -> ação de escrita (block_ip) é DENY —
    nenhum serviço automático consegue alterar estado real por padrão."""
    with cp.principal_context(rbac.SERVICE_MONITOR_PRINCIPAL):
        dec = cp.evaluate(cp.make_request("block_ip", target="203.0.113.10"))
    assert dec.decision is Decision.DENY


# ------------------------- 6: ask_agent propaga Service Principal ao CP -------------------------

class _CapturingAgent:
    """Stub do agente: captura o Principal ativo durante o invoke (sem LLM real)."""

    def __init__(self, sink):
        self.sink = sink

    def invoke(self, _state):
        self.sink.append(cp.get_current_principal())

        class _M:
            content = "ok"
        return {"messages": [_M()]}


def test_ask_agent_with_service_principal_propagates_to_control_plane(monkeypatch, tmp_path):
    import agents.runtime as runtime
    import database.db as db_module
    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "svc.db")
    db_module.init_db()

    sink: list = []
    monkeypatch.setattr(runtime, "get_agent", lambda: _CapturingAgent(sink))
    runtime.ask_agent(
        "ALERTA AUTOMÁTICO: teste de propagação de service principal",
        principal=rbac.SERVICE_MONITOR_PRINCIPAL,
    )
    assert sink[-1] == rbac.SERVICE_MONITOR_PRINCIPAL
    assert cp.get_current_principal() is None  # resetado após a execução


def test_ask_agent_audit_shows_service_actor_role_action_and_mode(monkeypatch, tmp_path):
    """Auditoria dentro do contexto de um Service Principal mostra actor,
    role, action_type e modo corretos (requisito da fase)."""
    import database.db as db_module
    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "svc_audit.db")
    db_module.init_db()

    with cp.principal_context(rbac.SERVICE_SIEM_PRINCIPAL):
        cp.evaluate(cp.make_request("block_ip", target="203.0.113.11"))

    with db_module.get_conn() as c:
        rows = c.execute(
            "SELECT detail FROM events WHERE event_type='control_plane_decision'"
        ).fetchall()
    blob = " ".join(r[0] or "" for r in rows)
    assert "actor=service:siem" in blob
    assert "role=service" in blob
    assert "action=block_ip" in blob
    assert "mode=" in blob


# ------------------------- 7: sem Principal = fallback documentado (só CLI/local) -------------------------

def test_ask_agent_without_principal_still_falls_back_to_local_admin_for_cli(monkeypatch, tmp_path):
    """Dívida DOCUMENTADA (não é bug desta fase): só o CLI local deve chamar
    ask_agent sem principal — nesse caso, o fallback explícito continua sendo
    local_admin/admin (contrato já existente desde a Fase 2, preservado aqui
    sem alteração). Os 4 call-sites de ask_agent em monitor_loop/
    proactive_audit_loop/reconcile_loop (main.py) ainda caem neste mesmo
    fallback hoje — migrá-los para os Service Principals desta fase fica para
    fases futuras pequenas, uma por loop (ver memória de continuidade)."""
    import agents.runtime as runtime
    import database.db as db_module
    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "cli_fallback.db")
    db_module.init_db()

    sink: list = []
    monkeypatch.setattr(runtime, "get_agent", lambda: _CapturingAgent(sink))
    runtime.ask_agent("oi")  # sem principal, como o CLI local faz
    assert sink[-1] == rbac.Principal(rbac.default_actor(), rbac.default_role())
    assert sink[-1] not in ALL_SERVICE_PRINCIPALS
