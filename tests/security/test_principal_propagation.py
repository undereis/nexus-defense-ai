"""Fase 2 — propagação de Principal via ContextVar (core/control_plane + runtime).

Cobre: make_request herda o Principal ativo; não usa admin implícito quando há
Principal propagado; contexto é resetado ao sair; execuções concorrentes não vazam
identidade; e o caminho CLI local (ask_agent sem principal) roda como local_admin
EXPLÍCITO. Sem LLM real, sem firewall/rede real.
"""

import threading

import agents.runtime as runtime
from core import control_plane as cp
from core import rbac
from core.models import Decision


# ------------------------- make_request herda o contexto -------------------------

def test_make_request_inherits_context_principal():
    with cp.principal_context(rbac.Principal("user:Ana", "noc_operator")):
        req = cp.make_request("block_ip", target="203.0.113.5")
    assert req.actor == "user:Ana" and req.role == "noc_operator"


def test_make_request_no_implicit_admin_when_principal_propagated():
    """Contexto API com Principal readonly -> make_request usa readonly, NÃO admin."""
    with cp.principal_context(rbac.Principal("user:Rui", "readonly")):
        req = cp.make_request("block_ip", target="203.0.113.5")
        dec = cp.evaluate(req)
    assert req.role == "readonly"
    assert dec.decision is Decision.DENY  # readonly não tem defense.block_ip


def test_explicit_actor_role_wins_over_context():
    with cp.principal_context(rbac.Principal("user:Ana", "readonly")):
        req = cp.make_request("block_ip", target="x", actor="api:main", role="admin")
    assert req.actor == "api:main" and req.role == "admin"


# ------------------------- reset do contexto -------------------------

def test_context_is_reset_after_block():
    assert cp.get_current_principal() is None
    with cp.principal_context(rbac.Principal("user:Ana", "readonly")):
        assert cp.get_current_principal().role == "readonly"
    assert cp.get_current_principal() is None                 # resetado
    # fora de contexto: fallback local/CLI (local_admin/admin)
    req = cp.make_request("block_ip", target="203.0.113.5")
    assert req.actor == "local_admin" and req.role == "admin"


def test_context_reset_even_on_exception():
    try:
        with cp.principal_context(rbac.Principal("user:Ana", "readonly")):
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    assert cp.get_current_principal() is None


# ------------------------- concorrência: sem vazamento -------------------------

def test_concurrent_principals_do_not_leak_via_contextvar():
    seen: dict[str, set] = {"readonly": set(), "admin": set()}
    barrier = threading.Barrier(2)

    def run(role: str):
        barrier.wait()
        with cp.principal_context(rbac.Principal(f"user:{role}", role)):
            for _ in range(80):
                seen[role].add(cp.make_request("block_ip", target="203.0.113.6").role)

    t1 = threading.Thread(target=run, args=("readonly",))
    t2 = threading.Thread(target=run, args=("admin",))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    assert seen["readonly"] == {"readonly"}   # nunca viu 'admin'
    assert seen["admin"] == {"admin"}         # nunca viu 'readonly'


# ------------------------- CLI local explícito + runtime -------------------------

class _CapturingAgent:
    """Stub do agente que captura o Principal ativo durante o invoke."""

    def __init__(self, sink):
        self.sink = sink

    def invoke(self, _state):
        self.sink.append(cp.get_current_principal())

        class _M:
            content = "ok"
        return {"messages": [_M()]}


def test_ask_agent_none_runs_as_explicit_local_admin(monkeypatch, tmp_path):
    """CLI local: ask_agent sem principal -> roda como local_admin/admin EXPLÍCITO,
    e o contexto é resetado ao final."""
    import database.db as db_module
    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "cli.db")
    db_module.init_db()

    sink: list = []
    monkeypatch.setattr(runtime, "get_agent", lambda: _CapturingAgent(sink))
    runtime.ask_agent("oi")  # sem principal (CLI)
    assert sink[-1] == rbac.Principal("local_admin", "admin")
    assert cp.get_current_principal() is None   # resetado após execução


def test_ask_agent_propagates_given_principal(monkeypatch, tmp_path):
    """API: ask_agent com Principal -> é ele que fica ativo durante o invoke."""
    import database.db as db_module
    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "api.db")
    db_module.init_db()

    sink: list = []
    monkeypatch.setattr(runtime, "get_agent", lambda: _CapturingAgent(sink))
    runtime.ask_agent("oi", principal=rbac.Principal("user:Rui", "readonly"))
    assert sink[-1] == rbac.Principal("user:Rui", "readonly")
    assert cp.get_current_principal() is None
