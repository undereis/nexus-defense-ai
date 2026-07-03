"""CP-SD Fase 4A — tools de deception/honeytoken migradas para o Control Plane.

Antes: plant_decoy_file e deploy_decoy_host chamavam o executor real DIRETO
(tools.honeytokens.plant_decoy_file / tools.deception.deploy_decoy_host), sem
RBAC nem auditoria de actor/role. Agora passam por cp.make_request +
cp.request_action antes do executor real (mesmo padrão de isolate_ip/release_ip).

plant_pppoe_honeytoken_username NÃO foi migrada nesta fase: é uma função pura
(tools.honeytokens.generate_decoy_pppoe_username só gera uma string aleatória,
sem I/O) — não há executor real para gatear.

Diferente da Fase 3 (onde o backstop do conftest bloqueia subprocess/requests),
aqui NÃO há backstop de filesystem — por isso TODO teste mocka explicitamente
tools.honeytokens.plant_decoy_file / tools.deception.deploy_decoy_host, mesmo
os de DENY, para garantir que nenhum teste escreva em disco de verdade.
"""

import pytest
from fastapi.testclient import TestClient

import agents.runtime as runtime
import api.server as server
import database.db as db_module
import tools.deception as deception
import tools.honeytokens as honeytokens
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

def test_plant_decoy_file_reaches_backend_via_cp(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        honeytokens, "plant_decoy_file",
        lambda kind, directory: calls.append((kind, directory)) or "isca plantada (fake)",
    )
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        out = nexus_agent.plant_decoy_file.invoke(
            {"kind": "aws_credentials", "directory": "/fake/backups"}
        )
    assert calls == [("aws_credentials", "/fake/backups")]
    assert "fake" in out


def test_deploy_decoy_host_reaches_backend_via_cp(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        deception, "deploy_decoy_host",
        lambda profile, ip=None: calls.append((profile, ip)) or "decoy declarado (fake)",
    )
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        out = nexus_agent.deploy_decoy_host.invoke({"profile": "database", "ip": "10.50.0.5"})
    assert calls == [("database", "10.50.0.5")]
    assert "fake" in out


# ------------------------- DENY (readonly): executor NUNCA chamado -------------------------

def test_deny_plant_decoy_file_never_writes_disk(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        honeytokens, "plant_decoy_file",
        lambda kind, directory: calls.append((kind, directory)) or "não deveria rodar",
    )
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("user:Ana", "readonly")):
        out = nexus_agent.plant_decoy_file.invoke(
            {"kind": "ssh_key", "directory": "/fake/backups"}
        )
    assert calls == []
    assert "NEGADO" in out


def test_deny_deploy_decoy_host_never_writes_db(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        deception, "deploy_decoy_host",
        lambda profile, ip=None: calls.append((profile, ip)) or "não deveria rodar",
    )
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("user:Ana", "readonly")):
        out = nexus_agent.deploy_decoy_host.invoke({"profile": "iot_camera", "ip": "10.50.0.6"})
    assert calls == []
    assert "NEGADO" in out


# ------------------------- lab/replay: nunca executa ação real -------------------------

def test_lab_mode_plant_decoy_file_no_real_call(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        honeytokens, "plant_decoy_file",
        lambda kind, directory: calls.append((kind, directory)) or "não deveria rodar",
    )
    operating_mode.set_operating_mode("lab")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        out = nexus_agent.plant_decoy_file.invoke(
            {"kind": "database_backup", "directory": "/fake/backups"}
        )
    assert calls == []
    assert "dry" in out.lower()


def test_replay_mode_deploy_decoy_host_no_real_call(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        deception, "deploy_decoy_host",
        lambda profile, ip=None: calls.append((profile, ip)) or "não deveria rodar",
    )
    operating_mode.set_operating_mode("replay")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        out = nexus_agent.deploy_decoy_host.invoke({"profile": "vpn_gateway", "ip": "10.50.0.7"})
    assert calls == []
    assert "dry" in out.lower()


# ------------------------- RBAC conservador: soc_analyst/noc_operator NÃO ganham deception.* -------------------------

def test_soc_analyst_denied_deception_actions_by_default(monkeypatch):
    """Decisão conservadora desta fase: só admin (wildcard "*") tem
    deception.*; soc_analyst/noc_operator não ganharam grant novo."""
    monkeypatch.setattr(honeytokens, "plant_decoy_file", lambda kind, directory: "não deveria rodar")
    monkeypatch.setattr(deception, "deploy_decoy_host", lambda profile, ip=None: "não deveria rodar")
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("user:Beto", "soc_analyst")):
        out1 = nexus_agent.plant_decoy_file.invoke({"kind": "aws_credentials", "directory": "/x"})
        out2 = nexus_agent.deploy_decoy_host.invoke({"profile": "backup", "ip": "10.50.0.8"})
    assert "NEGADO" in out1
    assert "NEGADO" in out2


# ------------------------- auditoria: actor/role reais -------------------------

def test_audit_records_real_actor_and_role(monkeypatch):
    monkeypatch.setattr(honeytokens, "plant_decoy_file", lambda kind, directory: "ok (fake)")
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        nexus_agent.plant_decoy_file.invoke({"kind": "aws_credentials", "directory": "/fake/x"})
    blob = _audit_blob()
    assert "actor=local_admin" in blob and "role=admin" in blob
    assert "action=plant_decoy_file" in blob


# ------------------------- /chat readonly: não executa -------------------------

class _FakeMsg:
    def __init__(self, content):
        self.content = content


class _PlantDecoyAgent:
    def invoke(self, _state):
        out = nexus_agent.plant_decoy_file.invoke(
            {"kind": "aws_credentials", "directory": "/fake/backups"}
        )
        return {"messages": [_FakeMsg(str(out))]}


class _DeployDecoyAgent:
    def invoke(self, _state):
        out = nexus_agent.deploy_decoy_host.invoke({"profile": "database", "ip": "10.50.0.9"})
        return {"messages": [_FakeMsg(str(out))]}


@pytest.fixture
def client():
    return TestClient(server.app)


def test_chat_readonly_cannot_plant_decoy_file(client, monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        honeytokens, "plant_decoy_file",
        lambda kind, directory: calls.append((kind, directory)) or "não deveria rodar",
    )
    monkeypatch.setattr(runtime, "get_agent", lambda: _PlantDecoyAgent())
    operating_mode.set_operating_mode("real")
    ro = users.create_user("Ana Readonly", "readonly")
    resp = client.post(
        "/chat", json={"message": "planta um arquivo isca"},
        headers={"Authorization": f"Bearer {ro['token']}"},
    )
    assert resp.status_code == 200
    assert calls == []


def test_chat_readonly_cannot_deploy_decoy_host(client, monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        deception, "deploy_decoy_host",
        lambda profile, ip=None: calls.append((profile, ip)) or "não deveria rodar",
    )
    monkeypatch.setattr(runtime, "get_agent", lambda: _DeployDecoyAgent())
    operating_mode.set_operating_mode("real")
    ro = users.create_user("Ana Readonly", "readonly")
    resp = client.post(
        "/chat", json={"message": "implanta um host isca"},
        headers={"Authorization": f"Bearer {ro['token']}"},
    )
    assert resp.status_code == 200
    assert calls == []


# ------------------------- Telegram/Slack readonly: não executa -------------------------

def test_telegram_readonly_cannot_plant_decoy_file(monkeypatch):
    from tools import noc_commands
    from tools import telegram as telegram_mod

    calls: list[tuple] = []
    monkeypatch.setattr(noc_commands, "handle_command", lambda t: None)  # força o agente
    monkeypatch.setattr(runtime, "get_agent", lambda: _PlantDecoyAgent())
    monkeypatch.setattr(
        honeytokens, "plant_decoy_file",
        lambda kind, directory: calls.append((kind, directory)) or "não deveria rodar",
    )
    monkeypatch.setattr(telegram_mod, "send_telegram_to", lambda cid, t: True)
    operating_mode.set_operating_mode("real")

    server._telegram_answer("planta um arquivo isca", chat_id=999)

    assert calls == []
    blob = _audit_blob()
    assert "actor=integration:telegram" in blob and "role=readonly" in blob


def test_slack_readonly_cannot_deploy_decoy_host(monkeypatch):
    import requests

    calls: list[tuple] = []
    monkeypatch.setattr(runtime, "get_agent", lambda: _DeployDecoyAgent())
    monkeypatch.setattr(
        deception, "deploy_decoy_host",
        lambda profile, ip=None: calls.append((profile, ip)) or "não deveria rodar",
    )
    monkeypatch.setattr(requests, "post", lambda *a, **k: None)
    operating_mode.set_operating_mode("real")

    server._answer_and_callback("implanta um host isca", "https://hooks.slack.test/x")

    assert calls == []
    blob = _audit_blob()
    assert "actor=integration:slack" in blob and "role=readonly" in blob
