import importlib

import pytest


@pytest.fixture
def db(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_correlation.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    import tools.threat_intel as ti
    importlib.reload(ti)
    yield dbmod, ti


def test_correlate_with_no_findings(db):
    _, ti = db
    result = ti.correlate("1.2.3.4")
    assert "Nenhuma auditoria de segurança prévia" in result


def test_correlate_with_prior_scan(db):
    dbmod, ti = db
    dbmod.record_threat_isolation("9.9.9.9")
    dbmod.record_finding("9.9.9.9", "nmap", "porta 22 aberta, OpenSSH 7.4 (CVE conhecido)")

    result = ti.correlate("9.9.9.9")
    assert "REINCIDENTE" in result
    assert "nmap" in result
    assert "porta 22 aberta" in result
    assert "AUDITORIAS PRÉVIAS" in result


def test_correlate_includes_multiple_findings(db):
    dbmod, ti = db
    dbmod.record_finding("8.8.8.8", "nmap", "achado 1")
    dbmod.record_finding("8.8.8.8", "nikto", "achado 2")

    result = ti.correlate("8.8.8.8")
    assert "2 encontrada" in result
    assert "achado 1" in result and "achado 2" in result
