import importlib

import pytest


@pytest.fixture
def db(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()
    yield dbmod


def test_log_event_and_list(db):
    db.log_event("ddos_suspect", "1.2.3.4", "teste", "isolado")
    db.record_blocked_ip("1.2.3.4", "teste")
    blocked = db.list_blocked_ips()
    assert blocked[0][0] == "1.2.3.4"


def test_save_and_load_messages(db):
    db.save_message("user", "oi")
    db.save_message("assistant", "olá")
    rows = db.get_recent_messages(limit=10)
    assert rows == [("user", "oi"), ("assistant", "olá")]


def test_remove_blocked_ip(db):
    db.record_blocked_ip("9.9.9.9", "teste")
    db.remove_blocked_ip("9.9.9.9")
    assert db.list_blocked_ips() == []
