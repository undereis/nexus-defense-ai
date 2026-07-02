"""Risco crítico #2 — /chat propaga o Principal real (Fase 2). CORRIGIDO.

Agora `api/server.chat` passa o Principal resolvido do token para `ask_agent`, que
o propaga às tools/Control Plane via ContextVar. Um token `readonly` não consegue
mais executar ação de escrita pelo /chat; `noc_operator` só faz o que o RBAC permite.

O teste NÃO chama o LLM: o AGENTE é stubado (um FakeAgent cujo `invoke` tenta bloquear
um IP), mas o `ask_agent` REAL roda — é ele que seta o `principal_context`. O executor
de firewall é um SPY: nenhum pfctl real roda.
"""

import pytest
from fastapi.testclient import TestClient

import agents.runtime as runtime
import api.server as server
import database.db as db_module
import tools.firewall as firewall
import tools.threat_intel as threat_intel
from core import operating_mode, users


class _FakeMsg:
    def __init__(self, content):
        self.content = content


class _FakeAgent:
    """Stub do agente: em vez do LLM, tenta bloquear um IP (ação de ESCRITA) —
    roda DENTRO do principal_context setado pelo ask_agent real."""

    def invoke(self, _state):
        from agents import nexus_agent
        out = nexus_agent.isolate_ip.invoke({"ip": "203.0.113.7", "reason": "via chat"})
        return {"messages": [_FakeMsg(f"resultado: {out}")]}


@pytest.fixture
def client():
    return TestClient(server.app)


@pytest.fixture
def block_spy(monkeypatch):
    """Executor real de firewall vira spy; agente vira o FakeAgent. Modo real."""
    calls: list[str] = []
    monkeypatch.setattr(firewall, "block_ip", lambda ip, reason="": calls.append(ip) or "ok (spy)")
    monkeypatch.setattr(threat_intel, "record_confirmed_isolation", lambda *a, **k: None)
    monkeypatch.setattr(runtime, "get_agent", lambda: _FakeAgent())
    operating_mode.set_operating_mode("real")  # isola do cinto de modo (Fase 1B)
    return calls


def _post_chat(client, token):
    return client.post(
        "/chat", json={"message": "bloqueia o ip 203.0.113.7"},
        headers={"Authorization": f"Bearer {token}"},
    )


# ------------------------- readonly: escrita negada -------------------------

def test_chat_readonly_must_not_execute_write(client, block_spy):
    """(Era xfail na Fase 1A) — readonly via /chat NÃO executa escrita."""
    ro = users.create_user("Ana Readonly", "readonly")
    resp = _post_chat(client, ro["token"])
    assert resp.status_code == 200
    assert block_spy == []   # executor real NUNCA chamado


def test_chat_readonly_does_not_operate_as_admin(client, block_spy):
    """A ação do agente é auditada com o papel REAL (readonly), não admin."""
    ro = users.create_user("Ana Readonly", "readonly")
    _post_chat(client, ro["token"])
    with db_module.get_conn() as c:
        rows = c.execute(
            "SELECT detail FROM events WHERE event_type='control_plane_decision'"
        ).fetchall()
    blob = " ".join(r[0] or "" for r in rows)
    assert "role=readonly" in blob          # papel real propagado
    assert "role=admin" not in blob         # NÃO operou como admin


# ------------------------- noc_operator: só o permitido -------------------------

def test_chat_noc_operator_can_block(client, block_spy):
    """noc_operator TEM defense.block_ip -> a escrita executa (via spy)."""
    noc = users.create_user("Beto NOC", "noc_operator")
    resp = _post_chat(client, noc["token"])
    assert resp.status_code == 200
    assert block_spy == ["203.0.113.7"]


def test_noc_operator_denied_offensive_action_at_policy():
    """noc_operator NÃO tem permissão ofensiva: sob o contexto dele, uma ação de
    exploit é NEGADA pela policy (só o permitido pelo RBAC)."""
    from core import control_plane as cp
    from core import rbac
    from core.models import Decision
    with cp.principal_context(rbac.Principal("api:noc", "noc_operator")):
        dec = cp.evaluate(cp.make_request("run_exploit", target="203.0.113.7"))
    assert dec.decision is Decision.DENY


# ------------------------- admin: comportamento preservado -------------------------

def test_chat_admin_can_block(client, block_spy):
    resp = _post_chat(client, server._runtime_token)  # token principal = admin
    assert resp.status_code == 200
    assert block_spy == ["203.0.113.7"]


# ------------------------- safety net de política (já valia) -------------------------

def test_readonly_role_denied_write_at_policy_level():
    from core import control_plane as cp
    from core.models import Decision
    dec = cp.evaluate(cp.make_request("block_ip", target="203.0.113.7", role="readonly"))
    assert dec.decision is Decision.DENY
