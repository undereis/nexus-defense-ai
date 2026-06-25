import importlib

import pytest


@pytest.fixture
def sqlmap_module(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_sqlmap.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    monkeypatch.setattr(config, "ALLOW_ACTIVE_EXPLOITATION", True)
    import tools.sqlmap_tool as sqlmap_mod
    importlib.reload(sqlmap_mod)
    monkeypatch.setattr(sqlmap_mod.shutil, "which", lambda name: "/usr/bin/sqlmap")
    yield sqlmap_mod, dbmod


def test_disabled_by_default(monkeypatch):
    import config
    monkeypatch.setattr(config, "ALLOW_ACTIVE_EXPLOITATION", False)
    import importlib
    import tools.sqlmap_tool as sqlmap_mod
    importlib.reload(sqlmap_mod)

    result = sqlmap_mod.run_sqlmap("https://example.com/?id=1")
    assert "DESATIVADO" in result
    importlib.reload(sqlmap_mod)


def test_rejects_invalid_url(sqlmap_module):
    sqlmap_mod, _ = sqlmap_module
    result = sqlmap_mod.run_sqlmap("not-a-url; rm -rf /")
    assert "inválida" in result


def test_rejects_invalid_level(sqlmap_module):
    sqlmap_mod, _ = sqlmap_module
    result = sqlmap_mod.run_sqlmap("https://example.com/?id=1", level="9")
    assert "level" in result


def test_rejects_invalid_risk(sqlmap_module):
    sqlmap_mod, _ = sqlmap_module
    result = sqlmap_mod.run_sqlmap("https://example.com/?id=1", risk="9")
    assert "risk" in result


def test_rejects_invalid_param(sqlmap_module):
    sqlmap_mod, _ = sqlmap_module
    result = sqlmap_mod.run_sqlmap("https://example.com/?id=1", param="id; drop table")
    assert "inválido" in result


def test_records_finding_on_success(sqlmap_module, monkeypatch):
    sqlmap_mod, dbmod = sqlmap_module

    class FakeResult:
        stdout = "Parameter 'id' is vulnerable. Type: boolean-based blind"
        stderr = ""

    monkeypatch.setattr(sqlmap_mod.subprocess, "run", lambda cmd, **k: FakeResult())
    result = sqlmap_mod.run_sqlmap("https://example.com/?id=1", param="id")

    assert "vulnerable" in result
    findings = dbmod.get_findings_for_host("https://example.com/?id=1")
    assert len(findings) == 1
    assert findings[0][0] == "sqlmap"
