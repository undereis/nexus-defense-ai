"""Fase 2: SSH / honeypot / social roteados EXPLICITAMENTE pelo Control Plane.

- SSH e honeypot via `request_action` (Pattern A): auditam execução, respeitam o
  modo operacional (honeypot em lab -> dry-run; SSH read-only roda em lab) e RBAC.
- Social via overlay `precheck_runtime` (Pattern B): RBAC + auditoria, SEM gate de
  aprovação (só gera texto; o envio real já é manual).

Hermético: DB temp + mocks object-form nos módulos subjacentes.
"""

import pytest

import config
import core.control_plane as cp
import database.db as db_module
from core import operating_mode
from core.models import Decision
from tools import access, honeypot, social_engineering


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "test.db")
    db_module.init_db()
    monkeypatch.setattr(config, "REQUIRE_ASSET_AUTHORIZATION", False, raising=False)
    yield


def _count_events(event_type: str) -> int:
    with db_module.get_conn() as c:
        return c.execute(
            "SELECT COUNT(*) FROM events WHERE event_type=?", (event_type,)
        ).fetchone()[0]


# ------------------------------ SSH ------------------------------

def test_ssh_executes_and_audits_in_real_mode(monkeypatch):
    from agents.nexus_agent import run_remote_command
    called = {}

    def fake(host, command, user, port):
        called.update(host=host, command=command)
        return "docker ps -> OK"

    monkeypatch.setattr(access, "ssh_run_command", fake)
    out = run_remote_command.invoke({"host": "192.0.2.10", "command": "docker ps"})
    assert "docker ps -> OK" in out
    assert called["host"] == "192.0.2.10"
    assert _count_events("control_plane_executed") >= 1


def test_ssh_still_runs_in_lab_because_readonly(monkeypatch):
    # SSH é read-only (changes_state=False) -> NÃO vira dry-run em lab.
    from agents.nexus_agent import run_remote_command
    monkeypatch.setattr(access, "ssh_run_command", lambda *a: "uptime -> OK")
    operating_mode.set_operating_mode("lab")
    out = run_remote_command.invoke({"host": "192.0.2.10", "command": "uptime"})
    assert "uptime -> OK" in out
    assert "dry-run" not in out.lower()


# ---------------------------- honeypot ----------------------------

def test_honeypot_start_executes_in_real_mode(monkeypatch):
    from agents.nexus_agent import start_honeypot
    calls = []
    monkeypatch.setattr(
        honeypot, "start",
        lambda service, port: calls.append((service, port)) or "honeypot ssh:2222 iniciado",
    )
    out = start_honeypot.invoke({"service": "ssh"})
    assert "iniciado" in out
    assert calls == [("ssh", 0)]


def test_honeypot_start_dry_run_in_lab(monkeypatch):
    from agents.nexus_agent import start_honeypot
    calls = []
    monkeypatch.setattr(honeypot, "start", lambda service, port: calls.append(1) or "NAO DEVERIA")
    operating_mode.set_operating_mode("lab")
    out = start_honeypot.invoke({"service": "ssh"})
    assert "dry-run" in out.lower()
    assert calls == []  # honeypot.start NUNCA é chamado em lab (não abre porta real)


def test_honeypot_stop_dry_run_in_lab(monkeypatch):
    from agents.nexus_agent import stop_honeypot
    calls = []
    monkeypatch.setattr(honeypot, "stop", lambda s, p: calls.append(1) or "parado")
    operating_mode.set_operating_mode("lab")
    out = stop_honeypot.invoke({})
    assert "dry-run" in out.lower()
    assert calls == []


# ----------------------------- social -----------------------------

def test_social_generates_in_real_admin(monkeypatch):
    from agents.nexus_agent import generate_social_engineering_content
    monkeypatch.setattr(
        social_engineering, "build_generation_request",
        lambda s, c, e: f"TEMPLATE[{s}] ref={e}",
    )
    out = generate_social_engineering_content.invoke({
        "scenario_type": "phishing_email", "context": "ctx", "engagement_reference": "SOW-1",
    })
    assert out.startswith("TEMPLATE[phishing_email]")


def test_social_denied_when_governance_denies(monkeypatch):
    from agents import nexus_agent

    class _Dec:
        decision = Decision.DENY
        reason = "papel 'readonly' não tem a permissão 'social.generate'."

    monkeypatch.setattr(cp, "precheck_runtime", lambda req: _Dec())
    generated = []
    monkeypatch.setattr(
        social_engineering, "build_generation_request",
        lambda *a: generated.append(1) or "NAO DEVERIA",
    )
    out = nexus_agent.generate_social_engineering_content.invoke({
        "scenario_type": "phishing_email", "context": "x", "engagement_reference": "SOW-1",
    })
    assert "NEGADO pela governança" in out
    assert generated == []  # não gerou nada quando a governança nega


def test_social_precheck_rbac_denies_readonly():
    # O wiring que a tool usa: papel sem 'social.generate' -> DENY.
    dec = cp.precheck_runtime(
        cp.make_request("social_engineering", role="readonly", engagement_reference="SOW-1")
    )
    assert dec.decision is Decision.DENY


# ---------------------------- catálogo ----------------------------

def test_catalog_has_routed_actions():
    from core.policy_engine import ACTION_CATALOG
    for action in ("ssh_command", "honeypot_start", "honeypot_stop", "social_engineering"):
        assert action in ACTION_CATALOG
