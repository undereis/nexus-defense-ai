"""Risco crítico #2 — /chat não pode operar como admin implícito.

Hoje `api/server.chat` chama `ask_agent(msg)` SEM propagar o Principal do token; o
agente monta suas ações com o ator/papel padrão (local_admin/admin). Resultado: um
token `readonly` que alcança /chat consegue induzir uma ESCRITA real (bloqueio de IP).

O teste NÃO chama o LLM: `ask_agent` é substituído por um fake que simula o agente
decidindo bloquear um IP (invoca a tool real `isolate_ip`, que roteia pelo Control
Plane). O executor de firewall é um SPY — nenhum pfctl real roda.

- `test_readonly_role_denied_write_at_policy_level`: passa HOJE — mostra que a policy
  engine JÁ nega escrita para readonly QUANDO o papel é conhecido. O que falta é a
  identidade CHEGAR até a ação (propagação — Fase B).
- `test_chat_readonly_must_not_execute_write`: xfail(strict) — demonstra o bypass:
  com token readonly, o bloqueio real acontece. Quando a Fase B propagar a identidade,
  a escrita será negada e o spy não será chamado -> o teste passa e o strict avisa.
"""

import pytest
from fastapi.testclient import TestClient

import api.server as server
import tools.firewall as firewall
import tools.threat_intel as threat_intel
from core import operating_mode, users
from core.models import Decision


@pytest.fixture
def client():
    return TestClient(server.app)


@pytest.fixture
def block_spy(monkeypatch):
    """Substitui o executor real de firewall por um spy: registra o alvo, sem SO."""
    calls: list[str] = []
    monkeypatch.setattr(firewall, "block_ip", lambda ip, reason="": calls.append(ip) or "ok (spy)")
    # isolate_ip também chama record_confirmed_isolation (que poderia reportar externo).
    monkeypatch.setattr(threat_intel, "record_confirmed_isolation", lambda *a, **k: None)
    return calls


def test_readonly_role_denied_write_at_policy_level():
    """Safety net (passa HOJE): quando o papel readonly É conhecido, a policy engine
    NEGA a escrita. A lacuna é a identidade não chegar aqui via /chat."""
    from core import control_plane as cp

    dec = cp.evaluate(cp.make_request("block_ip", target="203.0.113.7", role="readonly"))
    assert dec.decision is Decision.DENY


@pytest.mark.xfail(strict=True, reason=(
    "BYPASS Fase 0: /chat chama ask_agent sem propagar o Principal; o agente age como "
    "admin. Um token readonly dispara um bloqueio REAL. A Fase B deve propagar a "
    "identidade e a policy engine negar a escrita para readonly."))
def test_chat_readonly_must_not_execute_write(client, block_spy, monkeypatch):
    operating_mode.set_operating_mode("real")  # em real, a escrita executaria de fato
    readonly_user = users.create_user("Ana Readonly", "readonly")

    # Simula o agente decidindo bloquear um IP — SEM LLM real.
    def fake_ask(_message):
        from agents import nexus_agent
        return nexus_agent.isolate_ip.invoke({"ip": "203.0.113.7", "reason": "via chat"})

    monkeypatch.setattr(server, "ask_agent", fake_ask)

    resp = client.post(
        "/chat",
        json={"message": "bloqueia o ip 203.0.113.7"},
        headers={"Authorization": f"Bearer {readonly_user['token']}"},
    )
    assert resp.status_code == 200
    # Comportamento FUTURO esperado: readonly não pode causar escrita real.
    assert block_spy == []
