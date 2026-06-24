import importlib
import sqlite3

import pytest


@pytest.fixture
def db(monkeypatch, tmp_path):
    import config
    db_path = tmp_path / "test_audit.db"
    monkeypatch.setattr(config, "DB_PATH", db_path)
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    import tools.audit as audit
    importlib.reload(audit)
    yield dbmod, audit, db_path


def test_empty_chain_has_no_events(db):
    _, audit, _ = db
    result = audit.verify_chain()
    assert result.total_events == 0
    assert "Nenhum evento" in audit.describe(result)


def test_chain_intact_after_normal_logging(db):
    dbmod, audit, _ = db
    dbmod.log_event("a", "1.1.1.1", "primeiro", "")
    dbmod.log_event("b", "2.2.2.2", "segundo", "isolado")
    dbmod.log_event("c", None, "terceiro", "")

    result = audit.verify_chain()
    assert result.intact is True
    assert result.verified_events == 3
    assert result.broken_at_id is None


def test_each_event_links_to_previous_hash(db):
    dbmod, audit, _ = db
    dbmod.log_event("a", "1.1.1.1", "primeiro", "")
    dbmod.log_event("b", "2.2.2.2", "segundo", "")

    rows = dbmod.get_all_events()
    first, second = rows
    assert first[6] == dbmod.GENESIS_HASH  # prev_hash do primeiro é o genesis
    assert second[6] == first[7]  # prev_hash do segundo == entry_hash do primeiro


def test_tampering_with_detail_breaks_chain(db):
    dbmod, audit, db_path = db
    dbmod.log_event("a", "1.1.1.1", "original", "")
    dbmod.log_event("b", "2.2.2.2", "intacto", "")

    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE events SET detail = 'adulterado' WHERE event_type = 'a'")
    conn.commit()
    conn.close()

    result = audit.verify_chain()
    assert result.intact is False
    assert result.broken_at_id == 1
    assert "VIOLAÇÃO" in audit.describe(result)


def test_tampering_with_later_event_does_not_affect_earlier_verified_count(db):
    dbmod, audit, db_path = db
    dbmod.log_event("a", "1.1.1.1", "ok", "")
    dbmod.log_event("b", "2.2.2.2", "ok", "")
    dbmod.log_event("c", "3.3.3.3", "ok", "")

    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE events SET detail = 'forjado' WHERE event_type = 'c'")
    conn.commit()
    conn.close()

    result = audit.verify_chain()
    assert result.intact is False
    assert result.broken_at_id == 3
    assert result.verified_events == 2


def test_legacy_events_without_hash_dont_break_chain(db):
    dbmod, audit, db_path = db
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO events (event_type, source_ip, detail, action_taken) VALUES (?, ?, ?, ?)",
        ("legado", None, "evento de antes do hash chain", ""),
    )
    conn.commit()
    conn.close()

    dbmod.log_event("novo", "1.1.1.1", "evento com hash", "")

    result = audit.verify_chain()
    assert result.intact is True
    assert result.legacy_events == 1
    assert result.verified_events == 1
