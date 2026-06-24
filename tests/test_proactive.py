import importlib
from datetime import datetime, timedelta

import pytest

from tools.proactive import is_due


def test_never_scanned_is_always_due():
    assert is_due(None, interval_hours=24) is True


def test_recent_scan_is_not_due():
    now = datetime(2026, 1, 1, 12, 0, 0)
    last_scan = (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    assert is_due(last_scan, interval_hours=24, now=now) is False


def test_old_scan_is_due():
    now = datetime(2026, 1, 1, 12, 0, 0)
    last_scan = (now - timedelta(hours=25)).strftime("%Y-%m-%d %H:%M:%S")
    assert is_due(last_scan, interval_hours=24, now=now) is True


def test_exactly_at_interval_is_due():
    now = datetime(2026, 1, 1, 12, 0, 0)
    last_scan = (now - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    assert is_due(last_scan, interval_hours=24, now=now) is True


@pytest.fixture
def db(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_proactive.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    import tools.proactive as proactive
    importlib.reload(proactive)
    yield dbmod, proactive


def test_authorize_and_list(db):
    dbmod, proactive = db
    proactive.authorize("example.com", interval_hours=12)
    text = proactive.describe_monitored_assets()
    assert "example.com" in text
    assert "12" in text


def test_revoke_removes_asset(db):
    dbmod, proactive = db
    proactive.authorize("example.com")
    proactive.revoke("example.com")
    assert "Nenhum ativo" in proactive.describe_monitored_assets()


def test_get_due_assets_includes_never_scanned(db):
    dbmod, proactive = db
    proactive.authorize("never-scanned.com", interval_hours=24)
    assert "never-scanned.com" in proactive.get_due_assets()


def test_check_asset_records_finding_only_when_changed(db, monkeypatch):
    dbmod, proactive = db
    proactive.authorize("example.com")

    monkeypatch.setattr(
        "tools.proactive.recon.check_security_headers", lambda host: "resultado A"
    )
    changed, summary = proactive.check_asset("example.com")
    assert changed is True
    assert summary == "resultado A"
    assert len(dbmod.get_findings_for_host("example.com")) == 1

    # mesma checagem de novo, resultado idêntico -> não deve duplicar
    changed2, _ = proactive.check_asset("example.com")
    assert changed2 is False
    assert len(dbmod.get_findings_for_host("example.com")) == 1

    # resultado diferente -> deve gravar de novo
    monkeypatch.setattr(
        "tools.proactive.recon.check_security_headers", lambda host: "resultado B"
    )
    changed3, _ = proactive.check_asset("example.com")
    assert changed3 is True
    assert len(dbmod.get_findings_for_host("example.com")) == 2
