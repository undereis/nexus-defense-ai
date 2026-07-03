"""CP-SD Fase 4B — microcorreção: `command` cru de configure_network_device
nunca aparece em auditoria/summary/log, só dentro do executor real após ALLOW.

Sintaxe de config de rede (Cisco/Huawei/RouterOS) é espaço-separada, não
"chave=valor" — ex.: "username admin password X", "snmp-server community Y".
Os padrões de redaction em core/redaction.py foram reforçados para cobrir
isso (separador "=".":" OU espaço; "community" adicionado às chaves sensíveis;
mínimo de caracteres do token pós-"Bearer" reduzido — não assumir que um
segredo curto é seguro só por ser curto).

Este arquivo prova: a hash chain nunca grava o segredo cru; o summary da
confirmação fora de banda usa a versão redigida; o executor real, quando de
fato confirmado/executado, ainda recebe o command CRU (senão o comando de
configuração pararia de funcionar); DENY/DRY_RUN_ONLY nunca chamam o executor
nem vazam o command cru.
"""

import database.db as db_module
from agents import nexus_agent
from core import control_plane as cp
from core import operating_mode, rbac
from tools import risk as risk_gate


def _audit_blob() -> str:
    with db_module.get_conn() as c:
        rows = c.execute(
            "SELECT detail FROM events WHERE event_type IN "
            "('control_plane_decision', 'control_plane_executed', 'pending_action_created')"
        ).fetchall()
    return " ".join(r[0] or "" for r in rows)


def _extract_id(msg: str) -> int:
    return int(msg.split("id=")[1].split(")")[0])


def _real_code(action_id: int) -> str:
    from database.db import get_pending_action
    row = get_pending_action(action_id)
    return row[4]


# ------------------------- 1-4: segredo cru nunca na auditoria -------------------------

def test_command_with_password_not_raw_in_audit(monkeypatch):
    monkeypatch.setattr("tools.network_devices._raw_ssh", lambda *a, **k: "não deveria rodar")
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        nexus_agent.configure_network_device.invoke({
            "vendor": "cisco_ios", "host": "10.99.1.1",
            "command": "username admin password MinhaSenhaUnica123",
        })
    blob = _audit_blob()
    assert "MinhaSenhaUnica123" not in blob


def test_command_with_secret_not_raw_in_audit(monkeypatch):
    monkeypatch.setattr("tools.network_devices._raw_ssh", lambda *a, **k: "não deveria rodar")
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        nexus_agent.configure_network_device.invoke({
            "vendor": "cisco_ios", "host": "10.99.1.2",
            "command": "enable secret segredoUnico987",
        })
    blob = _audit_blob()
    assert "segredoUnico987" not in blob


def test_command_with_snmp_community_not_raw_in_audit(monkeypatch):
    monkeypatch.setattr("tools.network_devices._raw_ssh", lambda *a, **k: "não deveria rodar")
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        nexus_agent.configure_network_device.invoke({
            "vendor": "cisco_ios", "host": "10.99.1.3",
            "command": "snmp-server community publicComunidadeXYZ RO",
        })
    blob = _audit_blob()
    assert "publicComunidadeXYZ" not in blob


def test_command_with_authorization_bearer_not_raw_in_audit(monkeypatch):
    monkeypatch.setattr("tools.network_devices._raw_ssh", lambda *a, **k: "não deveria rodar")
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        nexus_agent.configure_network_device.invoke({
            "vendor": "linux", "host": "10.99.1.4",
            "command": "curl -H authorization Bearer tokenBearerUnico456 https://x",
        })
    blob = _audit_blob()
    assert "tokenBearerUnico456" not in blob


# ------------------------- 5: summary da confirmação usa command redigido -------------------------

def test_summary_uses_redacted_command_not_raw():
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        out = nexus_agent.configure_network_device.invoke({
            "vendor": "cisco_ios", "host": "10.99.1.5",
            "command": "username admin password SenhaVisivelNoSummary",
        })
    assert "SenhaVisivelNoSummary" not in out
    from core import redaction
    assert redaction.MASK in out
    # confere também a linha persistida em pending_actions.summary
    action_id = _extract_id(out)
    from database.db import get_pending_action
    row = get_pending_action(action_id)
    assert "SenhaVisivelNoSummary" not in row[3]  # summary


# ------------------------- 6: executor real recebe command CRU após confirmação -------------------------

def test_executor_receives_raw_command_only_after_confirmation(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        "tools.network_devices._raw_ssh",
        lambda host, command, user, port: calls.append((host, command)) or "executado (fake)",
    )
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        out = nexus_agent.configure_network_device.invoke({
            "vendor": "cisco_ios", "host": "10.99.1.6",
            "command": "username admin password SenhaCruParaExecutor",
        })
    assert calls == []  # ainda não executou (só pendente)
    action_id = _extract_id(out)
    result = risk_gate.confirm_and_execute(action_id, _real_code(action_id))
    assert "confirmada e executada" in result
    assert calls == [("10.99.1.6", "username admin password SenhaCruParaExecutor")]


# ------------------------- 7/8: DENY e DRY_RUN_ONLY não chamam executor nem vazam -------------------------

def test_deny_readonly_does_not_leak_raw_command(monkeypatch):
    monkeypatch.setattr("tools.network_devices._raw_ssh", lambda *a, **k: "não deveria rodar")
    operating_mode.set_operating_mode("real")
    with cp.principal_context(rbac.Principal("user:Ana", "readonly")):
        out = nexus_agent.configure_network_device.invoke({
            "vendor": "cisco_ios", "host": "10.99.1.7",
            "command": "username admin password SenhaQueNuncaDeveVazar",
        })
    assert "NEGADO" in out
    assert "SenhaQueNuncaDeveVazar" not in out
    blob = _audit_blob()
    assert "SenhaQueNuncaDeveVazar" not in blob


def test_dry_run_lab_mode_does_not_leak_raw_command(monkeypatch):
    monkeypatch.setattr("tools.network_devices._raw_ssh", lambda *a, **k: "não deveria rodar")
    operating_mode.set_operating_mode("lab")
    with cp.principal_context(rbac.Principal("local_admin", "admin")):
        out = nexus_agent.configure_network_device.invoke({
            "vendor": "cisco_ios", "host": "10.99.1.8",
            "command": "username admin password SenhaDryRunNuncaVaza",
        })
    assert "dry" in out.lower()
    assert "SenhaDryRunNuncaVaza" not in out
    blob = _audit_blob()
    assert "SenhaDryRunNuncaVaza" not in blob
