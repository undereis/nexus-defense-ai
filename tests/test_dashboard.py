"""Testes do dashboard web read-only (Frente H)."""

import pytest
from fastapi.testclient import TestClient

import api.server as server
import database.db as db_module
from tools import dashboard


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    db_module.init_db()
    yield


@pytest.fixture
def client():
    return TestClient(server.app)


def _seed():
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="pendente", days_overdue=9)
    db_module.set_subscriber_status("c1", "bloqueado_inadimplencia")
    db_module.add_monitored_device("d1", "10.0.0.1", name="OLT-1")
    db_module.set_device_status("d1", "offline")
    db_module.open_device_outage("d1", "10.0.0.1", "OLT-1", "ping")
    db_module.record_blocked_ip("198.51.100.7", "scan")
    db_module.log_event("ddos_severe", "198.51.100.7", "muito acima do normal")


# ---------- dados ----------

def test_dashboard_data_aggregates():
    _seed()
    d = dashboard.dashboard_data()
    assert d["subscribers"]["blocked"] == 1
    assert d["devices"]["offline"] == 1
    assert len(d["open_outages"]) == 1
    assert d["blocked_count"] == 1
    assert d["events_24h"] >= 1
    assert any(e["ip"] == "198.51.100.7" for e in d["recent_events"])


# ---------- endpoints ----------

def test_dashboard_page_served(client):
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "Nexus" in r.text


def test_dashboard_data_requires_token(client):
    r = client.get("/dashboard/data")
    assert r.status_code == 401


def test_dashboard_data_with_token(client):
    _seed()
    r = client.get("/dashboard/data",
                   headers={"Authorization": f"Bearer {server._runtime_token}"})
    assert r.status_code == 200
    body = r.json()
    assert body["subscribers"]["blocked"] == 1
    assert "recent_events" in body
