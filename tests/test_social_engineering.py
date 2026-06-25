import importlib

import pytest


@pytest.fixture
def se_module(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_se.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    monkeypatch.setattr(config, "ALLOW_SOCIAL_ENGINEERING", True)
    import tools.social_engineering as se
    importlib.reload(se)
    yield se, dbmod


def test_disabled_by_default_blocks(monkeypatch):
    import config
    monkeypatch.setattr(config, "ALLOW_SOCIAL_ENGINEERING", False)
    import importlib
    import tools.social_engineering as se
    importlib.reload(se)

    result = se.build_generation_request("phishing_email", "ctx", "SOW-1")
    assert "DESATIVADA" in result
    importlib.reload(se)


def test_requires_engagement_reference(se_module):
    se, _ = se_module
    result = se.build_generation_request("phishing_email", "ctx", "")
    assert "obrigatório" in result


def test_rejects_invalid_scenario_type(se_module):
    se, _ = se_module
    result = se.build_generation_request("invalido", "ctx", "SOW-1")
    assert "inválido" in result


@pytest.mark.parametrize("scenario", ["phishing_email", "vishing_script", "pretexting_scenario"])
def test_valid_scenarios_return_instructions(se_module, scenario):
    se, _ = se_module
    result = se.build_generation_request(scenario, "contexto de teste", "SOW-2026-042")
    assert "SOW-2026-042" in result
    assert "manual" in result.lower()


def test_generation_is_logged_with_audit_trail(se_module):
    se, dbmod = se_module
    se.build_generation_request("phishing_email", "contexto sigiloso", "SOW-99")

    events = dbmod.get_all_events()
    matching = [e for e in events if e[2] == "social_engineering_content_generated"]
    assert len(matching) == 1
    assert "SOW-99" in matching[0][4]
    assert matching[0][7] is not None  # entry_hash presente


def test_response_never_implies_autonomous_sending(se_module):
    se, _ = se_module
    result = se.build_generation_request("vishing_script", "ctx", "SOW-1")
    assert "envio" in result.lower() or "manual" in result.lower()
