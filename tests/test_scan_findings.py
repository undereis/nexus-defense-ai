import importlib

import pytest


@pytest.fixture
def db(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_findings.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()
    yield dbmod


def test_no_findings_for_unknown_host(db):
    assert db.get_findings_for_host("nunca-escaneado.com") == []


def test_record_and_retrieve_finding(db):
    db.record_finding("example.com", "nmap", "porta 80 aberta")
    rows = db.get_findings_for_host("example.com")
    assert len(rows) == 1
    assert rows[0][0] == "nmap"
    assert rows[0][1] == "porta 80 aberta"


def test_findings_ordered_most_recent_first(db):
    db.record_finding("example.com", "nmap", "primeiro scan")
    db.record_finding("example.com", "nikto", "segundo scan")
    rows = db.get_findings_for_host("example.com")
    assert rows[0][0] == "nikto"
    assert rows[1][0] == "nmap"


def test_list_scanned_hosts_counts_correctly(db):
    db.record_finding("a.com", "nmap", "x")
    db.record_finding("a.com", "nikto", "y")
    db.record_finding("b.com", "nmap", "z")
    rows = db.list_scanned_hosts()
    by_host = {r[0]: r[2] for r in rows}
    assert by_host["a.com"] == 2
    assert by_host["b.com"] == 1


def test_findings_isolated_per_host(db):
    db.record_finding("a.com", "nmap", "achado a")
    db.record_finding("b.com", "nmap", "achado b")
    assert len(db.get_findings_for_host("a.com")) == 1
    assert db.get_findings_for_host("a.com")[0][1] == "achado a"
