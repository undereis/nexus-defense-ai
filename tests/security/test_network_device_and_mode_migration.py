"""CP-SD Fase 4B — configure_network_device e set_operating_mode migrados
para o Control Plane.

configure_network_device: o ramo de LEITURA (comando na allowlist por vendor)
e o ramo de ESCRITA (qualquer coisa fora da allowlist, tratado como
configuração real) agora passam por cp.make_request+cp.request_action antes do
executor real. Achado: o ramo de escrita HOJE bypassa a governança por
completo — o tool_name "network_device_run_command" nunca esteve mapeado no
overlay de tools/risk.py (fora de escopo tocar esse arquivo nesta fase); em vez
disso o novo action_type é HIGH risco + aprovação, e o próprio
core/control_plane.request_action (já existente/testado) delega ao MESMO gate
de confirmação fora de banda de sempre.

set_operating_mode: antes, QUALQUER papel podia trocar o modo sem checagem de
RBAC (só era auditado depois do fato). Agora reaproveita a permissão
"system.operating_mode" (a mesma já usada pela REST em POST /api/mode).
changes_state=False é deliberado — ver core/policy_engine.py — para não travar
a própria saída de lab/replay de volta para real.

Nenhum SSH/rede/subprocess/socket real: tools.network_devices.run_read_command
/_raw_ssh e core.operating_mode.set_operating_mode são sempre mockados
diretamente (mesmo nos casos de DENY), já que não há backstop de subprocess
para esses módulos no conftest desta pasta.
"""

import pytest
from fastapi.testclient import TestClient

import agents.runtime as runtime
import api.server as server
import database.db as db_module
import tools.network_devices as network_devices
from agents import nexus_agent
from core import control_plane as cp
from core import operating_mode, rbac, users


def _audit_blob() -> str:
    with db_module.get_conn() as c:
        rows = c.execute(
            "SELECT detail FROM events WHERE event_type IN "
            "('control_plane_decision', 'control_plane_executed', 'pending_action_created')"
        ).fetchall()
    return " ".join(r[0] or "" for r in rows)


# ==================== PARTE A — configure_network_device ====================

# ------------------------- leitura: passa pelo CP -------------------------

def test_read_command_reaches_backend_via_cp(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        network_devices, "run_read_command",
        lambda vendor, host, command, user, port: calls.append((vendor, host, command)) or "ok (fake)",
    )
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        out = nexus_agent.configure_network_device.invoke(
            {"vendor": "linux", "host": "10.99.0.1", "command": "uptime"}
        )
    assert calls == [("linux", "10.99.0.1", "uptime")]
    assert "fake" in out


# ------------------------- escrita: passa pelo CP (aprovação) -------------------------

def test_write_command_creates_pending_action_via_cp(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        network_devices, "_raw_ssh",
        lambda host, command, user, port: calls.append((host, command)) or "não deveria executar direto",
    )
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        out = nexus_agent.configure_network_device.invoke(
            {"vendor": "cisco_ios", "host": "10.99.0.2", "command": "interface gi0/1"}
        )
    # aprovação humana: NÃO executa na hora, mas cria pendência
    assert calls == []
    assert "pendente" in out.lower() or "não executada" in out.lower()
    blob = _audit_blob()
    assert "action=network_device_write_command" in blob


# ------------------------- comando ambíguo: tratado como escrita -------------------------

def test_ambiguous_command_is_treated_as_write(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        network_devices, "_raw_ssh",
        lambda host, command, user, port: calls.append((host, command)) or "não deveria executar direto",
    )
    read_calls: list[tuple] = []
    monkeypatch.setattr(
        network_devices, "run_read_command",
        lambda vendor, host, command, user, port: read_calls.append(command) or "não deveria ler direto",
    )
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        nexus_agent.configure_network_device.invoke(
            {"vendor": "linux", "host": "10.99.0.3", "command": "algo totalmente desconhecido --xyz"}
        )
    assert calls == []          # não executou escrita direto (foi para aprovação)
    assert read_calls == []     # e não tratou como leitura
    blob = _audit_blob()
    assert "action=network_device_write_command" in blob


# ------------------------- DENY (readonly): executor NUNCA chamado -------------------------

def test_deny_write_command_never_calls_ssh(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        network_devices, "_raw_ssh",
        lambda host, command, user, port: calls.append((host, command)) or "não deveria rodar",
    )
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("user:Ana", "readonly")):
        out = nexus_agent.configure_network_device.invoke(
            {"vendor": "cisco_ios", "host": "10.99.0.4", "command": "no shutdown"}
        )
    assert calls == []
    assert "NEGADO" in out


# ------------------------- lab/replay: nunca executa escrita real -------------------------

def test_lab_mode_write_command_no_real_call(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        network_devices, "_raw_ssh",
        lambda host, command, user, port: calls.append((host, command)) or "não deveria rodar",
    )
    operating_mode.set_operating_mode("lab")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        out = nexus_agent.configure_network_device.invoke(
            {"vendor": "huawei_vrp", "host": "10.99.0.5", "command": "system-view"}
        )
    assert calls == []
    assert "dry" in out.lower()


def test_replay_mode_write_command_no_real_call(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        network_devices, "_raw_ssh",
        lambda host, command, user, port: calls.append((host, command)) or "não deveria rodar",
    )
    operating_mode.set_operating_mode("replay")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        out = nexus_agent.configure_network_device.invoke(
            {"vendor": "ubiquiti_edgeos", "host": "10.99.0.6", "command": "delete interfaces eth0"}
        )
    assert calls == []
    assert "dry" in out.lower()


# ------------------------- /chat readonly: não executa -------------------------

class _FakeMsg:
    def __init__(self, content):
        self.content = content


class _ConfigureDeviceAgent:
    def invoke(self, _state):
        out = nexus_agent.configure_network_device.invoke(
            {"vendor": "cisco_ios", "host": "10.99.0.7", "command": "no shutdown"}
        )
        return {"messages": [_FakeMsg(str(out))]}


class _SetModeAgent:
    def invoke(self, _state):
        out = nexus_agent.set_operating_mode.invoke({"mode": "real"})
        return {"messages": [_FakeMsg(str(out))]}


@pytest.fixture
def client():
    return TestClient(server.app)


def test_chat_readonly_cannot_configure_network_device(client, monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        network_devices, "_raw_ssh",
        lambda host, command, user, port: calls.append((host, command)) or "não deveria rodar",
    )
    monkeypatch.setattr(runtime, "get_agent", lambda: _ConfigureDeviceAgent())
    operating_mode.set_operating_mode("real")
    ro = users.create_user("Ana Readonly", "readonly")
    resp = client.post(
        "/chat", json={"message": "configura o dispositivo"},
        headers={"Authorization": f"Bearer {ro['token']}"},
    )
    assert resp.status_code == 200
    assert calls == []


# ------------------------- Telegram/Slack readonly: não executa -------------------------

def test_telegram_readonly_cannot_configure_network_device(monkeypatch):
    from tools import noc_commands
    from tools import telegram as telegram_mod

    calls: list[tuple] = []
    monkeypatch.setattr(noc_commands, "handle_command", lambda t: None)  # força o agente
    monkeypatch.setattr(runtime, "get_agent", lambda: _ConfigureDeviceAgent())
    monkeypatch.setattr(
        network_devices, "_raw_ssh",
        lambda host, command, user, port: calls.append((host, command)) or "não deveria rodar",
    )
    monkeypatch.setattr(telegram_mod, "send_telegram_to", lambda cid, t: True)
    operating_mode.set_operating_mode("real")

    server._telegram_answer("configura o dispositivo", chat_id=999)

    assert calls == []
    blob = _audit_blob()
    assert "actor=integration:telegram" in blob and "role=readonly" in blob


# ==================== PARTE B — set_operating_mode ====================

def test_admin_can_set_operating_mode_in_temp_db():
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        out = nexus_agent.set_operating_mode.invoke({"mode": "lab"})
    assert "lab" in out.lower()
    assert operating_mode.get_operating_mode() == "lab"
    blob = _audit_blob()
    assert "actor=local_admin" in blob and "role=admin" in blob
    assert "action=set_operating_mode" in blob


def test_set_operating_mode_escapes_lab_mode_as_admin():
    """changes_state=False é deliberado: mesmo com o modo ATUAL em lab, admin
    consegue voltar para 'real' — não fica preso (galinha-e-ovo)."""
    operating_mode.set_operating_mode("lab")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        out = nexus_agent.set_operating_mode.invoke({"mode": "real"})
    assert "real" in out.lower()
    assert "dry" not in out.lower()
    assert operating_mode.get_operating_mode() == "real"


def test_deny_readonly_cannot_set_operating_mode(monkeypatch):
    operating_mode.set_operating_mode("real")  # baseline REAL (unmocked) antes do patch
    calls: list[str] = []
    import core.operating_mode as operating_mode_mod
    monkeypatch.setattr(
        operating_mode_mod, "set_operating_mode",
        lambda mode: calls.append(mode) or "não deveria rodar",
    )
    with cp.principal_context(rbac.Principal("user:Ana", "readonly")):
        out = nexus_agent.set_operating_mode.invoke({"mode": "lab"})
    assert calls == []
    assert "NEGADO" in out
    assert operating_mode.get_operating_mode() == "real"  # modo não mudou


def test_chat_readonly_cannot_set_operating_mode(client, monkeypatch):
    operating_mode.set_operating_mode("real")  # baseline REAL (unmocked) antes do patch
    calls: list[str] = []
    import core.operating_mode as operating_mode_mod
    monkeypatch.setattr(
        operating_mode_mod, "set_operating_mode",
        lambda mode: calls.append(mode) or "não deveria rodar",
    )
    monkeypatch.setattr(runtime, "get_agent", lambda: _SetModeAgent())
    ro = users.create_user("Ana Readonly", "readonly")
    resp = client.post(
        "/chat", json={"message": "muda o modo para real"},
        headers={"Authorization": f"Bearer {ro['token']}"},
    )
    assert resp.status_code == 200
    assert calls == []


def test_slack_readonly_cannot_set_operating_mode(monkeypatch):
    import requests

    operating_mode.set_operating_mode("real")  # baseline REAL (unmocked) antes do patch
    calls: list[str] = []
    import core.operating_mode as operating_mode_mod
    monkeypatch.setattr(
        operating_mode_mod, "set_operating_mode",
        lambda mode: calls.append(mode) or "não deveria rodar",
    )
    monkeypatch.setattr(runtime, "get_agent", lambda: _SetModeAgent())
    monkeypatch.setattr(requests, "post", lambda *a, **k: None)

    server._answer_and_callback("muda o modo para real", "https://hooks.slack.test/x")

    assert calls == []
    blob = _audit_blob()
    assert "actor=integration:slack" in blob and "role=readonly" in blob
