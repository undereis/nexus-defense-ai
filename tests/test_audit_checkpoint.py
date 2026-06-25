import importlib
import sqlite3

import pytest


@pytest.fixture
def db(monkeypatch, tmp_path):
    import config
    db_path = tmp_path / "test_checkpoint.db"
    monkeypatch.setattr(config, "DB_PATH", db_path)
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    import tools.audit as audit
    importlib.reload(audit)
    yield dbmod, audit, db_path


def test_checkpoint_with_no_events(db):
    _, audit, _ = db
    result = audit.create_checkpoint()
    assert "Nenhum evento" in result


def test_checkpoint_created_without_notify_configured(db, monkeypatch):
    dbmod, audit, _ = db
    dbmod.log_event("a", "1.1.1.1", "evento", "")
    monkeypatch.setattr("tools.notify.send_notification", lambda *a, **k: False)

    result = audit.create_checkpoint()
    assert "SEM envio externo" in result

    checkpoint = dbmod.get_latest_audit_checkpoint()
    assert checkpoint is not None
    assert checkpoint[4] == 0  # sent_externally = False


def test_checkpoint_created_with_notify_configured(db, monkeypatch):
    dbmod, audit, _ = db
    dbmod.log_event("a", "1.1.1.1", "evento", "")
    monkeypatch.setattr("tools.notify.send_notification", lambda *a, **k: True)

    result = audit.create_checkpoint()
    assert "enviado externamente" in result

    checkpoint = dbmod.get_latest_audit_checkpoint()
    assert checkpoint[4] == 1  # sent_externally = True


def test_no_truncation_when_chain_matches_checkpoint(db, monkeypatch):
    dbmod, audit, _ = db
    dbmod.log_event("a", "1.1.1.1", "evento 1", "")
    dbmod.log_event("b", "2.2.2.2", "evento 2", "")
    monkeypatch.setattr("tools.notify.send_notification", lambda *a, **k: True)
    audit.create_checkpoint()

    result = audit.verify_chain()
    assert result.truncated is False
    assert result.intact is True


def test_detects_truncation_when_last_events_deleted(db, monkeypatch):
    dbmod, audit, db_path = db
    dbmod.log_event("a", "1.1.1.1", "evento 1", "")
    dbmod.log_event("b", "2.2.2.2", "evento 2", "")
    dbmod.log_event("c", "3.3.3.3", "evento 3 (será apagado)", "")
    monkeypatch.setattr("tools.notify.send_notification", lambda *a, **k: True)
    audit.create_checkpoint()

    # simula um atacante apagando o último evento direto no banco
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM events WHERE event_type = 'c'")
    conn.commit()
    conn.close()

    result = audit.verify_chain()
    assert result.truncated is True
    assert "checkpoint" in audit.describe(result).lower() or "TRUNCAMENTO" in audit.describe(result)


def test_truncation_note_mentions_proof_strength_based_on_external_send(db, monkeypatch):
    dbmod, audit, db_path = db
    dbmod.log_event("a", "1.1.1.1", "evento", "")
    monkeypatch.setattr("tools.notify.send_notification", lambda *a, **k: False)
    audit.create_checkpoint()

    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM events")
    conn.commit()
    conn.close()

    result = audit.verify_chain()
    assert result.truncated is True
    assert "indício, não prova definitiva" in result.checkpoint_note
