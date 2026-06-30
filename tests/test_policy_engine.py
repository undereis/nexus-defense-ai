"""Policy Engine determinística (Prioridade 2) — core/policy_engine.py.

Cobre as decisões críticas (P10): role sem permissão, alvo fora do inventário,
modo lab → dry-run, exploração ativa exige toggle + aprovação, engenharia social
exige engagement_reference, e o caminho ALLOW padrão (admin/real).
"""

import pytest

import config
import database.db as db_module
from core import control_plane as cp, operating_mode
from core.models import Decision
from core.policy_engine import evaluate


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "test.db")
    db_module.init_db()
    monkeypatch.setattr(config, "REQUIRE_ASSET_AUTHORIZATION", False, raising=False)
    yield


def test_allow_block_ip_admin_real():
    assert evaluate(cp.make_request("block_ip", "8.8.8.8")).decision is Decision.ALLOW


def test_readonly_denied_state_change():
    d = evaluate(cp.make_request("block_ip", "8.8.8.8", role="readonly"))
    assert d.decision is Decision.DENY


def test_loopback_hard_denied():
    assert evaluate(cp.make_request("block_ip", "127.0.0.1")).decision is Decision.DENY


def test_strict_mode_unauthorized_target_denied(monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_ASSET_AUTHORIZATION", True, raising=False)
    assert evaluate(cp.make_request("block_ip", "8.8.8.8")).decision is Decision.DENY


def test_offense_denied_without_toggle(monkeypatch):
    monkeypatch.setattr(config, "ALLOW_ACTIVE_EXPLOITATION", False, raising=False)
    assert evaluate(cp.make_request("run_exploit", "8.8.8.8")).decision is Decision.DENY


def test_offense_requires_approval_with_toggle(monkeypatch):
    monkeypatch.setattr(config, "ALLOW_ACTIVE_EXPLOITATION", True, raising=False)
    assert evaluate(cp.make_request("run_exploit", "8.8.8.8")).decision is Decision.REQUIRE_APPROVAL


def test_offense_denied_by_rbac_even_with_toggle(monkeypatch):
    monkeypatch.setattr(config, "ALLOW_ACTIVE_EXPLOITATION", True, raising=False)
    d = evaluate(cp.make_request("run_exploit", "8.8.8.8", role="soc_analyst"))
    assert d.decision is Decision.DENY  # soc_analyst não tem offense.*


def test_social_requires_engagement_reference(monkeypatch):
    monkeypatch.setattr(config, "ALLOW_SOCIAL_ENGINEERING", True, raising=False)
    assert evaluate(cp.make_request("social_engineering")).decision is Decision.DENY
    d = evaluate(cp.make_request("social_engineering", engagement_reference="ENG-2026-01"))
    assert d.decision is Decision.REQUIRE_APPROVAL  # alto risco


def test_lab_mode_dry_run_for_state_change():
    operating_mode.set_operating_mode("lab")
    assert evaluate(cp.make_request("block_ip", "8.8.8.8")).decision is Decision.DRY_RUN_ONLY


def test_replay_mode_dry_run_for_state_change():
    operating_mode.set_operating_mode("replay")
    assert evaluate(cp.make_request("block_subscriber", "sub-1")).decision is Decision.DRY_RUN_ONLY


def test_lab_mode_allows_read():
    operating_mode.set_operating_mode("lab")
    assert evaluate(cp.make_request("read")).decision is Decision.ALLOW


def test_high_risk_infra_requires_approval():
    assert evaluate(cp.make_request("mikrotik_write", "8.8.8.8")).decision is Decision.REQUIRE_APPROVAL
