"""Testes da fachada de API para clientes (tools/noc_api.py) e dos endpoints
/api/* (api/server.py). Cobre formato dos dados, auth por token e as ações."""

import pytest
from fastapi.testclient import TestClient

import api.server as server
import database.db as db_module
from tools import noc_api


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    db_module.init_db()
    yield


@pytest.fixture
def client():
    return TestClient(server.app)


def _auth():
    return {"Authorization": f"Bearer {server._runtime_token}"}


@pytest.fixture
def fake_mikrotik(monkeypatch):
    from tools import billing
    monkeypatch.setattr(billing.mikrotik, "block_subscriber_ip",
                        lambda ip: f"IP {ip} bloqueado (forward/drop).")
    monkeypatch.setattr(billing.mikrotik, "unblock_subscriber_ip",
                        lambda ip: f"IP {ip} desbloqueado (1 regra(s) removida(s)).")


def _seed():
    db_module.add_subscriber("c1", "203.0.113.5", name="Cliente 1",
                             invoice_status="pendente", days_overdue=9)
    db_module.add_monitored_device("d1", "10.0.0.1", name="OLT-1")
    db_module.set_device_status("d1", "offline")
    db_module.open_device_outage("d1", "10.0.0.1", "OLT-1", "ping")


# ---------- fachada (sem HTTP) ----------

def test_subscribers_shape():
    _seed()
    rows = noc_api.subscribers()
    assert rows[0]["id"] == "c1" and rows[0]["invoice_status"] == "pendente"


def test_devices_and_outages_shape():
    _seed()
    assert noc_api.devices()[0]["status"] == "offline"
    assert noc_api.outages()[0]["device_id"] == "d1"


# ---------- HTTP: auth ----------

def test_api_requires_token(client):
    assert client.get("/api/subscribers").status_code == 401
    assert client.post("/api/devices/check").status_code == 401


def test_api_overview_with_token(client):
    _seed()
    r = client.get("/api/overview", headers=_auth())
    assert r.status_code == 200
    assert "subscribers" in r.json()


def test_api_lists_with_token(client):
    _seed()
    subs = client.get("/api/subscribers", headers=_auth()).json()["subscribers"]
    assert subs[0]["id"] == "c1"
    devs = client.get("/api/devices", headers=_auth()).json()["devices"]
    assert devs[0]["status"] == "offline"


# ---------- HTTP: ações ----------

def test_api_block_and_unblock(client, fake_mikrotik):
    _seed()
    r = client.post("/api/subscribers/c1/block", headers=_auth())
    assert r.status_code == 200 and "OK" in r.json()["message"]
    assert db_module.get_subscriber("c1")[5] == "bloqueado_inadimplencia"

    r = client.post("/api/subscribers/c1/unblock", headers=_auth())
    assert "OK" in r.json()["message"]
    assert db_module.get_subscriber("c1")[5] == "ativo"


def test_api_billing_dry_run(client, fake_mikrotik):
    _seed()
    r = client.post("/api/billing/run?dry_run=true", headers=_auth())
    assert r.status_code == 200 and "DRY-RUN" in r.json()["message"]
    # dry-run não altera status
    assert db_module.get_subscriber("c1")[5] == "ativo"


def test_api_health(client):
    r = client.get("/api/health", headers=_auth())
    assert r.status_code == 200 and "AUTODIAGNÓSTICO" in r.json()["report"]
