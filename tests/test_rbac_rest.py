"""RBAC real na API REST: o token resolve um PAPEL, passado ao Control Plane.

O token principal é admin (compatível com hoje); tokens de NEXUS_ROLE_TOKENS
mapeiam para papéis com menos permissão. Uma ação de bloqueio com token
readonly/auditor é NEGADA pela governança; com admin/noc_operator, executa.
"""

import pytest
from fastapi.testclient import TestClient

import api.server as server
import database.db as db_module


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "test.db")
    db_module.init_db()
    yield


@pytest.fixture
def client():
    return TestClient(server.app)


@pytest.fixture
def fake_mikrotik(monkeypatch):
    from tools import billing
    monkeypatch.setattr(billing.mikrotik, "block_subscriber_ip", lambda ip: f"IP {ip} bloqueado.")


def _seed():
    db_module.add_subscriber("c1", "203.0.113.5", name="C1",
                             invoice_status="pendente", days_overdue=9)


def test_resolve_role_admin_is_main_token():
    assert server._resolve_role(server._runtime_token) == "admin"
    assert server._resolve_role("token-errado") is None


def test_role_token_map_parsing(monkeypatch):
    monkeypatch.setattr(server, "NEXUS_ROLE_TOKENS", "noc_operator:tk1, auditor:tk2", raising=False)
    m = server._role_token_map()
    assert m == {"tk1": "noc_operator", "tk2": "auditor"}


def test_invalid_token_401(client):
    r = client.post("/api/subscribers/c1/block", headers={"Authorization": "Bearer errado"})
    assert r.status_code == 401


def test_readonly_token_denied(client, monkeypatch):
    monkeypatch.setattr(server, "_ROLE_TOKENS", {"tok_ro": "readonly"})
    _seed()
    r = client.post("/api/subscribers/c1/block", headers={"Authorization": "Bearer tok_ro"})
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "deny" and body["status"] == "denied"


def test_admin_token_executes(client, fake_mikrotik):
    _seed()
    r = client.post("/api/subscribers/c1/block",
                    headers={"Authorization": f"Bearer {server._runtime_token}"})
    assert r.status_code == 200 and r.json()["decision"] == "allow"


def test_noc_operator_can_block(client, fake_mikrotik, monkeypatch):
    monkeypatch.setattr(server, "_ROLE_TOKENS", {"tok_noc": "noc_operator"})
    _seed()
    r = client.post("/api/subscribers/c1/block", headers={"Authorization": "Bearer tok_noc"})
    assert r.status_code == 200 and r.json()["decision"] == "allow"
