"""Integração total: tools de alto risco roteadas pelo Control Plane no gate
de confirmação (tools/risk.py `_governance_precheck`).

Garante que o overlay de governança (RBAC + trava de segurança + modo
operacional) atua ANTES de criar a pendência, sem quebrar o caminho normal
(real/admin) nem afetar tool_names não mapeados.
"""

import pytest

import config
import database.db as db_module
from core import operating_mode
from tools import risk


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "test.db")
    db_module.init_db()
    monkeypatch.setattr(config, "REQUIRE_ASSET_AUTHORIZATION", False, raising=False)
    monkeypatch.setattr(risk, "_notify_out_of_band", lambda *a, **k: None)
    yield


def test_real_admin_creates_pending():
    risk.register_action("mikrotik_add_firewall_rule", lambda **kw: "ok")
    msg = risk.request_confirmation("mikrotik_add_firewall_rule", "add rule", src_address="203.0.113.5")
    assert "pendente" in msg.lower()
    assert len(db_module.list_pending_actions()) == 1


def test_lab_mode_blocks_state_change_no_pending():
    operating_mode.set_operating_mode("lab")
    risk.register_action("mikrotik_add_firewall_rule", lambda **kw: "ok")
    msg = risk.request_confirmation("mikrotik_add_firewall_rule", "add rule", src_address="203.0.113.5")
    assert "dry-run" in msg.lower()
    assert db_module.list_pending_actions() == []


def test_loopback_target_denied_no_pending():
    risk.register_action("run_exploit_module", lambda **kw: "ok")
    msg = risk.request_confirmation("run_exploit_module", "exploit", target="127.0.0.1")
    assert "NEGADA" in msg
    assert db_module.list_pending_actions() == []


def test_unmapped_tool_not_routed():
    risk.register_action("some_custom_action", lambda **kw: "ok")
    msg = risk.request_confirmation("some_custom_action", "x", value=1)
    assert "pendente" in msg.lower()  # tool_name não mapeado: governança não atua


def test_skip_policy_bypasses_precheck():
    operating_mode.set_operating_mode("lab")
    risk.register_action("mikrotik_add_firewall_rule", lambda **kw: "ok")
    msg = risk.request_confirmation(
        "mikrotik_add_firewall_rule", "x", src_address="203.0.113.5", _skip_policy=True
    )
    assert "pendente" in msg.lower()  # bypass → cria pendência mesmo em lab
    assert len(db_module.list_pending_actions()) == 1


def test_precheck_is_audited():
    operating_mode.set_operating_mode("lab")
    risk.register_action("asn_block_execute", lambda **kw: "ok")
    risk.request_confirmation("asn_block_execute", "x", asn="AS64496")
    blob = " ".join(str(e) for e in db_module.get_all_events())
    assert "control_plane_precheck" in blob
