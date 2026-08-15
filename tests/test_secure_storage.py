"""Regressões dos limites de armazenamento e autenticação local."""

import stat

import pytest


def test_database_is_created_owner_only(tmp_path, monkeypatch):
    import database.db as db_module

    db_path = tmp_path / "nexus.db"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    db_module.init_db()

    assert stat.S_IMODE(db_path.stat().st_mode) == 0o600


def test_api_rejects_missing_administrative_token():
    from api.server import _require_configured_token

    with pytest.raises(RuntimeError, match="NEXUS_API_TOKEN ausente"):
        _require_configured_token("")


def test_api_accepts_configured_administrative_token():
    from api.server import _require_configured_token

    assert _require_configured_token("configured-token") == "configured-token"
