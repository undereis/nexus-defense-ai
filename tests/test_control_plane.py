"""Control Plane (Prioridade 1) — core/control_plane.py.

Cobre a orquestração: ALLOW executa; DENY/DRY_RUN/REQUIRE_APPROVAL NÃO executam;
auditoria de cada decisão na hash chain; redaction de segredo nos params.
"""

import pytest

import config
import database.db as db_module
from core import control_plane as cp, operating_mode
from core.models import ActionStatus


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "test.db")
    db_module.init_db()
    monkeypatch.setattr(config, "REQUIRE_ASSET_AUTHORIZATION", False, raising=False)
    yield


def _counter_executor(box):
    def ex(ip=None, reason=None, **_):
        box["n"] += 1
        box["ip"] = ip
        return f"executado para {ip}"
    return ex


def test_allow_executes():
    box = {"n": 0}
    req = cp.make_request("block_ip", "8.8.8.8", params={"ip": "8.8.8.8", "reason": "r"})
    res = cp.request_action(req, executor=_counter_executor(box), tool_name="t_block")
    assert res.status is ActionStatus.EXECUTED
    assert box["n"] == 1 and box["ip"] == "8.8.8.8"
    assert "executado" in res.output


def test_deny_does_not_execute():
    box = {"n": 0}
    req = cp.make_request("block_ip", "127.0.0.1", params={"ip": "127.0.0.1", "reason": "r"})
    res = cp.request_action(req, executor=_counter_executor(box), tool_name="t_block_dny")
    assert res.status is ActionStatus.DENIED and box["n"] == 0


def test_readonly_role_denied_not_executed():
    box = {"n": 0}
    req = cp.make_request("block_ip", "8.8.8.8", role="readonly",
                          params={"ip": "8.8.8.8", "reason": "r"})
    res = cp.request_action(req, executor=_counter_executor(box), tool_name="t_block_ro")
    assert res.status is ActionStatus.DENIED and box["n"] == 0


def test_lab_mode_dry_run_does_not_execute():
    operating_mode.set_operating_mode("lab")
    box = {"n": 0}
    req = cp.make_request("block_ip", "8.8.8.8", params={"ip": "8.8.8.8", "reason": "r"})
    res = cp.request_action(req, executor=_counter_executor(box), tool_name="t_block_lab")
    assert res.status is ActionStatus.DRY_RUN and box["n"] == 0


def test_high_risk_requires_approval_does_not_execute(monkeypatch):
    from tools import risk as risk_gate
    monkeypatch.setattr(risk_gate, "_notify_out_of_band", lambda *a, **k: None)
    box = {"n": 0}
    req = cp.make_request("mikrotik_write", "8.8.8.8", params={"ip": "8.8.8.8", "reason": "r"})
    res = cp.request_action(req, executor=_counter_executor(box), tool_name="t_mik")
    assert res.status is ActionStatus.AWAITING_APPROVAL and box["n"] == 0
    # criou uma ação pendente reutilizando o gate existente
    assert "pendente" in res.output.lower()


def test_audit_redacts_secret_in_params():
    req = cp.make_request("block_ip", "8.8.8.8",
                          params={"ip": "8.8.8.8", "password": "hunter2secret"})
    cp.request_action(req, executor=lambda ip=None, password=None, **_: "ok", tool_name="t_red")
    blob = " ".join(str(e) for e in db_module.get_all_events())
    assert "hunter2secret" not in blob
    assert "control_plane_executed" in blob  # mas a decisão/execução FOI auditada


def test_decision_audited_for_deny():
    req = cp.make_request("block_ip", "127.0.0.1", params={"ip": "127.0.0.1"})
    cp.request_action(req, executor=lambda **_: "x", tool_name="t_audit_deny")
    blob = " ".join(str(e) for e in db_module.get_all_events())
    assert "control_plane_decision" in blob and "deny" in blob
