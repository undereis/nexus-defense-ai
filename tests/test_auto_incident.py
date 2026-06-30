"""Auto-incidente (INT-3) — incidents.auto_open_from_event + hook do honeypot.

Garante opt-in (default off), idempotência por (ip, kind), e o hook do honeypot
abrindo/reaproveitando o incidente quando ligado — sem nunca derrubar o processamento.
"""

import pytest

import config
import database.db as db_module
from tools import incidents


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "test.db")
    db_module.init_db()
    yield


def test_disabled_by_default(monkeypatch):
    monkeypatch.setattr(config, "AUTO_INCIDENT_ENABLED", False, raising=False)
    assert incidents.auto_open_from_event("honeypot", "203.0.113.5") is None
    assert db_module.list_incidents() == []


def test_opens_when_enabled(monkeypatch):
    monkeypatch.setattr(config, "AUTO_INCIDENT_ENABLED", True, raising=False)
    iid = incidents.auto_open_from_event("honeypot", "203.0.113.5", detail="hit em ssh:22")
    assert iid == 1
    row = db_module.get_incident(1)
    assert row[5] == "203.0.113.5" and row[1].startswith("[honeypot]")


def test_idempotent_same_ip_kind(monkeypatch):
    monkeypatch.setattr(config, "AUTO_INCIDENT_ENABLED", True, raising=False)
    a = incidents.auto_open_from_event("honeypot", "203.0.113.5")
    b = incidents.auto_open_from_event("honeypot", "203.0.113.5")
    assert a == b  # reaproveita o mesmo incidente
    assert len(db_module.list_incidents()) == 1
    # mas anotou o novo evento na timeline
    assert "novo evento [honeypot]" in incidents.incident_report(a)


def test_different_ip_opens_new(monkeypatch):
    monkeypatch.setattr(config, "AUTO_INCIDENT_ENABLED", True, raising=False)
    incidents.auto_open_from_event("honeypot", "203.0.113.5")
    incidents.auto_open_from_event("honeypot", "198.51.100.7")
    assert len(db_module.list_incidents()) == 2


def test_resolved_incident_does_not_block_new(monkeypatch):
    monkeypatch.setattr(config, "AUTO_INCIDENT_ENABLED", True, raising=False)
    a = incidents.auto_open_from_event("honeypot", "203.0.113.5")
    incidents.set_incident_status(a, "resolved")
    b = incidents.auto_open_from_event("honeypot", "203.0.113.5")
    assert b != a and len(db_module.list_incidents()) == 2  # o resolvido não dedupe


def test_honeypot_hook_opens_incident(monkeypatch):
    monkeypatch.setattr(config, "AUTO_INCIDENT_ENABLED", True, raising=False)
    from tools import honeypot

    monkeypatch.setattr(honeypot.firewall, "block_ip", lambda ip, reason: f"IP {ip} bloqueado.")
    honeypot._process_hit("203.0.113.9", 2222, "ssh")
    rows = db_module.list_incidents()
    assert len(rows) == 1 and rows[0][5] == "203.0.113.9"
