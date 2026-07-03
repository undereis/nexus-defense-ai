"""Fase 3 — tools diretas do agente migradas para o Control Plane.

Antes: release_ip, throttle_ip, release_ip_throttle e report_ip_to_abuseipdb
chamavam o executor real DIRETO (firewall.*/threat_feeds.*), sem RBAC nem
auditoria de actor/role — um Principal readonly propagado pela Fase 2 podia
ser IGNORADO por essas 4 tools.

Agora todas passam por cp.make_request + cp.request_action antes do executor
real (mesmo padrão de isolate_ip): DENY/DRY_RUN_ONLY nunca chamam o executor;
lab/replay não executam ação real; admin em modo real preserva o comportamento
de antes; a auditoria registra o actor/role reais.

Sem firewall/rede real: firewall.*/threat_feeds.report_to_abuseipdb são
monkeypatchados nos testes "positivos" (que provam a chamada real). Nos
testes de DENY, propositalmente NÃO mockamos o executor: se ele fosse chamado
por engano, o backstop do conftest (subprocess/requests bloqueados) derrubaria
o teste com AssertionError — prova mais forte que apenas checar uma lista vazia.
"""

import pytest
from fastapi.testclient import TestClient

import agents.runtime as runtime
import api.server as server
import database.db as db_module
import tools.firewall as firewall
import tools.threat_feeds as threat_feeds
from agents import nexus_agent
from core import control_plane as cp
from core import operating_mode, rbac, users


def _audit_blob() -> str:
    with db_module.get_conn() as c:
        rows = c.execute(
            "SELECT detail FROM events WHERE event_type IN "
            "('control_plane_decision', 'control_plane_executed')"
        ).fetchall()
    return " ".join(r[0] or "" for r in rows)


# ------------------------- admin/real: comportamento preservado -------------------------

def test_release_ip_reaches_backend_via_cp(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(firewall, "unblock_ip", lambda ip: calls.append(ip) or "ok")
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        out = nexus_agent.release_ip.invoke({"ip": "203.0.113.10"})
    assert calls == ["203.0.113.10"]
    assert "ok" in out


def test_throttle_ip_reaches_backend_via_cp(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        firewall, "rate_limit_ip", lambda ip, reason="": calls.append((ip, reason)) or "ok"
    )
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        nexus_agent.throttle_ip.invoke({"ip": "203.0.113.11", "reason": "teste"})
    assert calls == [("203.0.113.11", "teste")]


def test_release_ip_throttle_reaches_backend_via_cp(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(firewall, "unrate_limit_ip", lambda ip: calls.append(ip) or "ok")
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        nexus_agent.release_ip_throttle.invoke({"ip": "203.0.113.12"})
    assert calls == ["203.0.113.12"]


def test_report_ip_to_abuseipdb_reaches_backend_via_cp(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        threat_feeds, "report_to_abuseipdb",
        lambda ip, categories, comment: calls.append(ip) or "ok",
    )
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        nexus_agent.report_ip_to_abuseipdb.invoke({"ip": "203.0.113.13", "reason": "scan"})
    assert calls == ["203.0.113.13"]


# ------------------------- DENY (readonly): executor NUNCA chamado -------------------------
# Sem monkeypatch do executor: se fosse chamado, o backstop do conftest (subprocess/
# requests bloqueados) levantaria AssertionError e o teste falharia por exceção.

def test_deny_release_ip_never_calls_firewall_backend():
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("user:Ana", "readonly")):
        out = nexus_agent.release_ip.invoke({"ip": "203.0.113.14"})
    assert "NEGADO" in out


def test_deny_throttle_ip_never_calls_firewall_backend():
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("user:Ana", "readonly")):
        out = nexus_agent.throttle_ip.invoke({"ip": "203.0.113.15", "reason": "x"})
    assert "NEGADO" in out


def test_deny_release_ip_throttle_never_calls_firewall_backend():
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("user:Ana", "readonly")):
        out = nexus_agent.release_ip_throttle.invoke({"ip": "203.0.113.16"})
    assert "NEGADO" in out


def test_deny_report_ip_to_abuseipdb_never_calls_requests_post():
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("user:Ana", "readonly")):
        out = nexus_agent.report_ip_to_abuseipdb.invoke({"ip": "203.0.113.17", "reason": "x"})
    assert "NEGADO" in out


# ------------------------- lab/replay: nunca executa ação real -------------------------

def test_lab_mode_release_ip_no_real_call(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(firewall, "unblock_ip", lambda ip: calls.append(ip) or "ok")
    operating_mode.set_operating_mode("lab")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        out = nexus_agent.release_ip.invoke({"ip": "203.0.113.18"})
    assert calls == []
    assert "dry" in out.lower()


def test_lab_mode_throttle_ip_no_real_call(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(firewall, "rate_limit_ip", lambda ip, reason="": calls.append(ip) or "ok")
    operating_mode.set_operating_mode("lab")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        out = nexus_agent.throttle_ip.invoke({"ip": "203.0.113.19", "reason": "x"})
    assert calls == []
    assert "dry" in out.lower()


def test_replay_mode_release_ip_throttle_no_real_call(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(firewall, "unrate_limit_ip", lambda ip: calls.append(ip) or "ok")
    operating_mode.set_operating_mode("replay")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        out = nexus_agent.release_ip_throttle.invoke({"ip": "203.0.113.20"})
    assert calls == []
    assert "dry" in out.lower()


def test_replay_mode_report_ip_to_abuseipdb_no_real_call(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        threat_feeds, "report_to_abuseipdb",
        lambda ip, categories, comment: calls.append(ip) or "ok",
    )
    operating_mode.set_operating_mode("replay")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        out = nexus_agent.report_ip_to_abuseipdb.invoke({"ip": "203.0.113.21", "reason": "x"})
    assert calls == []
    assert "dry" in out.lower()


# ------------------------- noc_operator: só o que o RBAC concede -------------------------

def test_noc_operator_can_release_ip_but_not_throttle(monkeypatch):
    """noc_operator TEM defense.unblock_ip (RBAC já existente) mas NÃO tem
    defense.rate_limit_ip (decisão conservadora desta fase: não afrouxar/ampliar
    grants sem pedido explícito)."""
    release_calls: list[str] = []
    throttle_calls: list[str] = []
    monkeypatch.setattr(firewall, "unblock_ip", lambda ip: release_calls.append(ip) or "ok")
    monkeypatch.setattr(
        firewall, "rate_limit_ip", lambda ip, reason="": throttle_calls.append(ip) or "ok"
    )
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("user:Beto", "noc_operator")):
        nexus_agent.release_ip.invoke({"ip": "203.0.113.22"})
        out = nexus_agent.throttle_ip.invoke({"ip": "203.0.113.23", "reason": "x"})
    assert release_calls == ["203.0.113.22"]
    assert throttle_calls == []
    assert "NEGADO" in out


# ------------------------- auditoria: actor/role reais -------------------------

def test_audit_records_real_actor_and_role(monkeypatch):
    monkeypatch.setattr(firewall, "unblock_ip", lambda ip: "ok")
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("user:Beto", "noc_operator")):
        nexus_agent.release_ip.invoke({"ip": "203.0.113.24"})
    blob = _audit_blob()
    assert "actor=user:Beto" in blob and "role=noc_operator" in blob
    assert "role=admin" not in blob


# ------------------------- /chat readonly: não executa -------------------------

class _FakeMsg:
    def __init__(self, content):
        self.content = content


class _ReleaseIpAgent:
    def invoke(self, _state):
        out = nexus_agent.release_ip.invoke({"ip": "203.0.113.25"})
        return {"messages": [_FakeMsg(str(out))]}


class _ThrottleIpAgent:
    def invoke(self, _state):
        out = nexus_agent.throttle_ip.invoke({"ip": "203.0.113.26", "reason": "via chat"})
        return {"messages": [_FakeMsg(str(out))]}


@pytest.fixture
def client():
    return TestClient(server.app)


def test_chat_readonly_cannot_release_ip(client, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(firewall, "unblock_ip", lambda ip: calls.append(ip) or "ok")
    monkeypatch.setattr(runtime, "get_agent", lambda: _ReleaseIpAgent())
    operating_mode.set_operating_mode("real")
    ro = users.create_user("Ana Readonly", "readonly")
    resp = client.post(
        "/chat", json={"message": "libera o ip 203.0.113.25"},
        headers={"Authorization": f"Bearer {ro['token']}"},
    )
    assert resp.status_code == 200
    assert calls == []


def test_chat_readonly_cannot_throttle_ip(client, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(firewall, "rate_limit_ip", lambda ip, reason="": calls.append(ip) or "ok")
    monkeypatch.setattr(runtime, "get_agent", lambda: _ThrottleIpAgent())
    operating_mode.set_operating_mode("real")
    ro = users.create_user("Ana Readonly", "readonly")
    resp = client.post(
        "/chat", json={"message": "throttle o ip 203.0.113.26"},
        headers={"Authorization": f"Bearer {ro['token']}"},
    )
    assert resp.status_code == 200
    assert calls == []


# ------------------------- Telegram/Slack readonly: não executa -------------------------

def test_telegram_readonly_cannot_release_ip(monkeypatch):
    from tools import noc_commands
    from tools import telegram as telegram_mod

    calls: list[str] = []
    monkeypatch.setattr(noc_commands, "handle_command", lambda t: None)  # força o agente
    monkeypatch.setattr(runtime, "get_agent", lambda: _ReleaseIpAgent())
    monkeypatch.setattr(firewall, "unblock_ip", lambda ip: calls.append(ip) or "ok")
    monkeypatch.setattr(telegram_mod, "send_telegram_to", lambda cid, t: True)
    operating_mode.set_operating_mode("real")

    server._telegram_answer("libera o ip 203.0.113.25", chat_id=999)

    assert calls == []
    blob = _audit_blob()
    assert "actor=integration:telegram" in blob and "role=readonly" in blob


def test_slack_readonly_cannot_throttle_ip(monkeypatch):
    import requests

    calls: list[str] = []
    monkeypatch.setattr(runtime, "get_agent", lambda: _ThrottleIpAgent())
    monkeypatch.setattr(firewall, "rate_limit_ip", lambda ip, reason="": calls.append(ip) or "ok")
    monkeypatch.setattr(requests, "post", lambda *a, **k: None)
    operating_mode.set_operating_mode("real")

    server._answer_and_callback("throttle o ip 203.0.113.26", "https://hooks.slack.test/x")

    assert calls == []
    blob = _audit_blob()
    assert "actor=integration:slack" in blob and "role=readonly" in blob
