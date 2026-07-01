"""Fase 3: usuários reais da API REST + RBAC rico (core/users.py, api/server.py).

Token gravado só como HASH; papel granular resolvido do token; RBAC por
permissão nas rotas de billing/devices (403). Hermético: DB temp.
"""

import pytest
from fastapi.testclient import TestClient

import api.server as server
import database.db as db_module
from core import users


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "test.db")
    db_module.init_db()
    yield


@pytest.fixture
def client():
    return TestClient(server.app)


def _hdr(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ------------------------------ core.users ------------------------------

def test_create_user_returns_token_once_and_stores_only_hash():
    u = users.create_user("Alice", "noc_operator")
    assert u["role"] == "noc_operator" and u["token"]
    assert u["user_id"].startswith("usr_")
    rows = db_module.list_api_users()
    assert len(rows) == 1
    # o token cru NUNCA está no banco (só o hash + a dica mascarada)
    assert u["token"] not in str(rows[0])


def test_resolve_user_roundtrip():
    u = users.create_user("Bob", "auditor")
    got = users.resolve_user(u["token"])
    assert got is not None and got["role"] == "auditor" and got["name"] == "Bob"
    assert users.resolve_user("token-errado") is None
    assert users.resolve_user("") is None


def test_invalid_role_raises_without_admin_fallback():
    with pytest.raises(ValueError):
        users.create_user("X", "superadmin")  # não vira admin silenciosamente


def test_revoke_disables_token_idempotent():
    u = users.create_user("Carol", "readonly")
    assert users.resolve_user(u["token"]) is not None
    assert users.revoke_user(u["user_id"]) is True
    assert users.resolve_user(u["token"]) is None      # revogado não resolve mais
    assert users.revoke_user(u["user_id"]) is False     # idempotente


def test_list_users_never_leaks_token():
    u = users.create_user("Dan", "soc_analyst")
    lst = users.list_users()
    assert lst[0]["role"] == "soc_analyst" and lst[0]["enabled"] is True
    assert "token" not in lst[0] and "token_hash" not in lst[0]
    assert u["token"] not in str(lst[0])


# -------------------- api/server: resolução de principal --------------------

def test_principal_precedence():
    assert server._resolve_principal(server._runtime_token).role == "admin"
    assert server._resolve_principal("nada") is None
    u = users.create_user("Eve", "noc_operator")
    p = server._resolve_principal(u["token"])
    assert p.role == "noc_operator" and p.actor == "user:Eve"
    # compat: _resolve_role continua devolvendo string p/ os testes antigos
    assert server._resolve_role(u["token"]) == "noc_operator"


# ----------------- api/server: DB user autentica + RBAC nas rotas -----------------

def test_db_user_can_read(client):
    u = users.create_user("Frank", "readonly")
    assert client.get("/api/subscribers", headers=_hdr(u["token"])).status_code == 200


def test_readonly_denied_on_billing(client):
    u = users.create_user("Gina", "readonly")
    r = client.post("/api/billing/run?dry_run=true", headers=_hdr(u["token"]))
    assert r.status_code == 403


def test_noc_operator_allowed_on_billing(client):
    u = users.create_user("Hugo", "noc_operator")
    r = client.post("/api/billing/run?dry_run=true", headers=_hdr(u["token"]))
    assert r.status_code == 200


def test_readonly_denied_on_devices_check(client):
    u = users.create_user("Ivan", "readonly")
    r = client.post("/api/devices/check", headers=_hdr(u["token"]))
    assert r.status_code == 403


def test_revoked_user_gets_401(client):
    u = users.create_user("Joana", "noc_operator")
    users.revoke_user(u["user_id"])
    assert client.get("/api/subscribers", headers=_hdr(u["token"])).status_code == 401


# ------------------------------- agent tool -------------------------------

def test_list_api_users_tool_no_token_leak():
    from agents.nexus_agent import list_api_users
    users.create_user("Kate", "auditor")
    out = list_api_users.invoke({})
    assert "auditor" in out and "Kate" in out
    assert "Bearer" not in out
