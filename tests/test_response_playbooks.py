"""Playbooks determinísticos de resposta (Prioridade 9) — core/response_playbooks.py.

Garante que cada playbook existe e que a classificação das ações reflete a
governança real (policy engine): real/admin → AUTO para block_ip; readonly →
BLOQUEADA; lab → DRY-RUN; toggle off → BLOQUEADA para asn_block.
"""

import pytest

import config
import database.db as db_module
from core import operating_mode, response_playbooks


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "test.db")
    db_module.init_db()
    monkeypatch.setattr(config, "REQUIRE_ASSET_AUTHORIZATION", False, raising=False)
    yield


def _labels(plan, action_type):
    return [c["label"] for c in plan["classified_actions"] if c["action_type"] == action_type]


def test_all_expected_playbooks_present():
    expected = {"ddos", "suspect_ip", "honeypot_hit", "credential_stuffing",
                "device_down", "firewall_drift", "mikrotik_change", "authorized_brute_force"}
    assert expected <= set(response_playbooks.PLAYBOOKS)


def test_list_and_unknown():
    assert "ddos" in response_playbooks.list_playbooks()
    assert "não encontrado" in response_playbooks.plan_report("inexistente")


def test_ddos_block_ip_auto_in_real_admin():
    plan = response_playbooks.build_plan("ddos", target="203.0.113.5")
    assert _labels(plan, "block_ip") == ["AUTO"]


def test_ddos_asn_block_blocked_without_toggle(monkeypatch):
    monkeypatch.setattr(config, "ALLOW_ASN_BLOCK", False, raising=False)
    plan = response_playbooks.build_plan("ddos", target="203.0.113.5")
    assert _labels(plan, "asn_block") == ["BLOQUEADA"]


def test_readonly_role_blocks_block_ip():
    plan = response_playbooks.build_plan("honeypot_hit", target="203.0.113.5", role="readonly")
    assert _labels(plan, "block_ip") == ["BLOQUEADA"]


def test_lab_mode_makes_block_ip_dry_run():
    operating_mode.set_operating_mode("lab")
    plan = response_playbooks.build_plan("ddos", target="203.0.113.5")
    assert _labels(plan, "block_ip") == ["DRY-RUN"]


def test_mikrotik_change_requires_approval():
    plan = response_playbooks.build_plan("mikrotik_change", target="203.0.113.5")
    assert _labels(plan, "mikrotik_write") == ["APROVAÇÃO"]


def test_report_has_sections():
    rep = response_playbooks.plan_report("ddos", target="203.0.113.5")
    assert "Gatilho:" in rep and "Evidências necessárias:" in rep
    assert "Ações recomendadas:" in rep and "Classificação das ações" in rep
