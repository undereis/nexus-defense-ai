"""Fase 4: sincronização de modo Tauri<->backend — endpoints GET/POST /api/mode.

Leitura por qualquer token; escrita gated por 'system.operating_mode' (admin).
O cliente reflete o modo EFETIVO do backend. Hermético: DB temp.
"""

import pytest
from fastapi.testclient import TestClient

import api.server as server
import database.db as db_module
from core import operating_mode, users


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "test.db")
    db_module.init_db()
    yield


@pytest.fixture
def client():
    return TestClient(server.app)


def _admin():
    return {"Authorization": f"Bearer {server._runtime_token}"}


def _hdr(token):
    return {"Authorization": f"Bearer {token}"}


def test_get_mode_requires_token(client):
    assert client.get("/api/mode").status_code == 401


def test_get_mode_default_real(client):
    r = client.get("/api/mode", headers=_admin())
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "real" and body["allows_real_state_change"] is True
    assert set(body["valid_modes"]) == {"real", "lab", "replay"}


def test_admin_can_switch_to_lab(client):
    r = client.post("/api/mode", json={"mode": "lab"}, headers=_admin())
    assert r.status_code == 200
    assert r.json()["mode"] == "lab"
    assert r.json()["allows_real_state_change"] is False
    # persistiu no backend (fonte da verdade) e reflete no GET
    assert operating_mode.get_operating_mode() == "lab"
    assert client.get("/api/mode", headers=_admin()).json()["mode"] == "lab"


def test_invalid_mode_400(client):
    r = client.post("/api/mode", json={"mode": "turbo"}, headers=_admin())
    assert r.status_code == 400
    assert operating_mode.get_operating_mode() == "real"  # não mudou


def test_readonly_user_cannot_switch_mode(client):
    u = users.create_user("Ana", "readonly")
    r = client.post("/api/mode", json={"mode": "lab"}, headers=_hdr(u["token"]))
    assert r.status_code == 403
    assert operating_mode.get_operating_mode() == "real"  # inalterado


def test_noc_operator_cannot_switch_mode(client):
    u = users.create_user("Beto", "noc_operator")
    r = client.post("/api/mode", json={"mode": "lab"}, headers=_hdr(u["token"]))
    assert r.status_code == 403


def test_readonly_can_read_mode(client):
    u = users.create_user("Cid", "readonly")
    assert client.get("/api/mode", headers=_hdr(u["token"])).status_code == 200
