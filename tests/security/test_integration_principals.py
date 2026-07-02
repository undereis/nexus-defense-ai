"""Fase 2B — integrações externas (Telegram/Slack) usam Principal explícito.

Antes: Telegram/Slack chamavam ask_agent(text) sem Principal -> o agente rodava como
local_admin/admin implícito. Agora passam um service principal `readonly` conservador:
respondem perguntas (tools de leitura) mas NÃO executam ação de escrita pelo agente.

Sem LLM real (agente stubado), sem firewall/rede real (spies), sem Mikrotik.
"""

import inspect

import agents.runtime as runtime
import api.server as server
import database.db as db_module
import tools.firewall as firewall
import tools.threat_intel as threat_intel
from core import operating_mode


class _FakeMsg:
    def __init__(self, content):
        self.content = content


class _IsolateAgent:
    """Stub do agente que tenta uma ação de ESCRITA (bloquear IP), rodando dentro do
    principal_context setado pelo ask_agent real."""

    def invoke(self, _state):
        from agents import nexus_agent
        out = nexus_agent.isolate_ip.invoke({"ip": "203.0.113.7", "reason": "x"})
        return {"messages": [_FakeMsg(str(out))]}


def _decisions_blob() -> str:
    with db_module.get_conn() as c:
        rows = c.execute(
            "SELECT detail FROM events WHERE event_type='control_plane_decision'"
        ).fetchall()
    return " ".join(r[0] or "" for r in rows)


# ------------------------- guardas estáticos -------------------------

def test_external_callsites_pass_principal():
    """Nenhum call-site externo de ask_agent sem Principal explícito."""
    for fn, name in ((server._telegram_answer, "telegram"), (server._answer_and_callback, "slack")):
        src = inspect.getsource(fn)
        assert "ask_agent(" in src
        assert "principal=" in src, f"{name}: ask_agent chamado sem principal explícito"


def test_integration_principals_are_readonly_not_admin():
    assert server._TELEGRAM_PRINCIPAL.actor == "integration:telegram"
    assert server._TELEGRAM_PRINCIPAL.role == "readonly"
    assert server._SLACK_PRINCIPAL.actor == "integration:slack"
    assert server._SLACK_PRINCIPAL.role == "readonly"
    assert server._TELEGRAM_PRINCIPAL.role != "admin"
    assert server._SLACK_PRINCIPAL.role != "admin"


# ------------------------- Telegram: readonly, sem escrita -------------------------

def test_telegram_readonly_denies_write_and_audits_integration(monkeypatch):
    from tools import noc_commands
    from tools import telegram as telegram_mod

    monkeypatch.setattr(noc_commands, "handle_command", lambda t: None)  # força o agente
    monkeypatch.setattr(runtime, "get_agent", lambda: _IsolateAgent())
    calls: list[str] = []
    monkeypatch.setattr(firewall, "block_ip", lambda ip, reason="": calls.append(ip) or "ok")
    monkeypatch.setattr(threat_intel, "record_confirmed_isolation", lambda *a, **k: None)
    monkeypatch.setattr(telegram_mod, "send_telegram_to", lambda cid, t: True)
    operating_mode.set_operating_mode("real")  # isola do cinto de modo (Fase 1B)

    server._telegram_answer("bloqueia 203.0.113.7", chat_id=999)

    assert calls == []                                   # escrita NEGADA (readonly)
    blob = _decisions_blob()
    assert "actor=integration:telegram" in blob and "role=readonly" in blob
    assert "role=admin" not in blob                      # não operou como admin


# ------------------------- Slack: readonly, sem escrita -------------------------

def test_slack_readonly_denies_write_and_audits_integration(monkeypatch):
    import requests

    monkeypatch.setattr(runtime, "get_agent", lambda: _IsolateAgent())
    calls: list[str] = []
    monkeypatch.setattr(firewall, "block_ip", lambda ip, reason="": calls.append(ip) or "ok")
    monkeypatch.setattr(threat_intel, "record_confirmed_isolation", lambda *a, **k: None)
    # O callback do Slack faz requests.post; o backstop do conftest levanta
    # AssertionError (não RequestException, propagaria). Re-mocko para no-op.
    monkeypatch.setattr(requests, "post", lambda *a, **k: None)
    operating_mode.set_operating_mode("real")

    server._answer_and_callback("bloqueia 203.0.113.7", "https://hooks.slack.test/x")

    assert calls == []
    blob = _decisions_blob()
    assert "actor=integration:slack" in blob and "role=readonly" in blob
    assert "role=admin" not in blob
