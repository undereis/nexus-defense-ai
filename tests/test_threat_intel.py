import importlib

import pytest


@pytest.fixture
def db(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_threat.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    import tools.threat_intel as ti
    importlib.reload(ti)
    yield dbmod, ti


def test_unknown_ip_is_not_repeat_offender(db):
    _, ti = db
    assert ti.is_repeat_offender("1.2.3.4") is False
    assert "não tem histórico" in ti.describe_history("1.2.3.4")


def test_flagging_increments_history(db):
    dbmod, ti = db
    dbmod.record_threat_flag("1.2.3.4")
    dbmod.record_threat_flag("1.2.3.4")
    history = dbmod.get_threat_history("1.2.3.4")
    assert history[2] == 2  # times_flagged
    assert history[3] == 0  # times_isolated


def test_isolation_makes_repeat_offender(db):
    dbmod, ti = db
    dbmod.record_threat_isolation("9.9.9.9")
    assert ti.is_repeat_offender("9.9.9.9") is True
    assert "REINCIDENTE" in ti.describe_history("9.9.9.9")


def test_reputation_score_weighs_isolation_higher():
    from tools.threat_intel import reputation_score
    assert reputation_score(times_flagged=5, times_isolated=0) == 10
    assert reputation_score(times_flagged=0, times_isolated=1) == 10
    assert reputation_score(times_flagged=2, times_isolated=2) == 24


def test_list_repeat_offenders_orders_by_isolation(db):
    dbmod, ti = db
    dbmod.record_threat_flag("1.1.1.1")
    dbmod.record_threat_isolation("2.2.2.2")
    dbmod.record_threat_isolation("2.2.2.2")
    text = ti.describe_repeat_offenders()
    assert text.index("2.2.2.2") < text.index("1.1.1.1")
