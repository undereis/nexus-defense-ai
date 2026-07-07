"""CP-SD Fase 6B — loops internos simples de main.py migrados ao Control Plane.

Antes: risk_sweep_loop/audit_checkpoint_loop/watchdog_loop/report_loop chamavam
sua tool diretamente (sem ask_agent no meio, então não havia onde passar
`principal=`) — bypass total de RBAC/modo/auditoria. Agora cada um monta um
ActionRequest via cp.make_request (dentro de um principal_context com
SERVICE_WATCHDOG_PRINCIPAL — reaproveitado para os 4, já que nenhum dos outros
9 Service Principals da Fase 5A é um encaixe semântico melhor, e criar um novo
está fora do escopo desta fase) e só executa a tool real via
cp.request_action, na branch ALLOW.

3 dos 4 (risk.sweep_expired/audit.checkpoint/watchdog.check_health) têm
changes_state=True — em lab/replay viram dry-run. report.generate tem
changes_state=False DE PROPÓSITO (só lê e devolve texto; o notify/log do
resumo continuam fora do executor, em main.py, como já era) — não é afetado
pelo cinto de modo, só pelo RBAC.

Nenhum loop real roda: cada função de loop é chamada uma vez com um
stop_event cujo `.wait()` já seta o evento (uma iteração só, sem while
infinito real). As 4 tools (sweep_expired/create_checkpoint/check_and_heal/
generate_summary_report) são sempre mockadas — nenhum firewall/rede/
AbuseIPDB/Mikrotik/subprocess real, nenhum banco real tocado.
"""

import inspect
import threading

import main as main_module
from core import operating_mode, rbac
from core.models import Decision


def _audit_blob() -> str:
    import database.db as db_module
    with db_module.get_conn() as c:
        rows = c.execute(
            "SELECT detail FROM events WHERE event_type IN "
            "('control_plane_decision', 'control_plane_executed')"
        ).fetchall()
    return " ".join(r[0] or "" for r in rows)


def _one_iteration(monkeypatch, loop_fn):
    """Roda uma função de loop por EXATAMENTE uma iteração: stop_event.wait()
    já seta o evento na primeira chamada, então o `while not
    stop_event.is_set()` do topo encerra no início da segunda volta — sem
    while infinito real, sem sleep real."""
    stop_event = threading.Event()
    monkeypatch.setattr(stop_event, "wait", lambda timeout=None: stop_event.set())
    loop_fn(stop_event)


def _mock_common(monkeypatch):
    monkeypatch.setattr(main_module, "send_notification", lambda *a, **k: None)
    monkeypatch.setattr(main_module, "log_event", lambda *a, **k: None)
    monkeypatch.setattr(main_module, "_announce", lambda *a, **k: None)


# ------------------------- 1: cada loop passa pelo CP com SERVICE_WATCHDOG_PRINCIPAL -------------------------

def test_audit_checkpoint_loop_uses_service_watchdog_principal(monkeypatch):
    _mock_common(monkeypatch)
    calls: list = []
    monkeypatch.setattr(main_module, "create_checkpoint", lambda: calls.append(1) or "checkpoint (fake)")
    operating_mode.set_operating_mode("real")

    _one_iteration(monkeypatch, main_module.audit_checkpoint_loop)

    assert calls == [1]
    blob = _audit_blob()
    assert "actor=service:watchdog" in blob and "role=service" in blob
    assert "action=audit.checkpoint" in blob


def test_watchdog_loop_uses_service_watchdog_principal_and_announces_healed(monkeypatch):
    _mock_common(monkeypatch)
    announced: list = []
    monkeypatch.setattr(main_module, "_announce", lambda msg: announced.append(msg))
    monkeypatch.setattr(main_module, "check_and_heal", lambda: ["ssh:2222"])
    operating_mode.set_operating_mode("real")

    _one_iteration(monkeypatch, main_module.watchdog_loop)

    assert announced == ["Watchdog reergueu: ssh:2222"]
    blob = _audit_blob()
    assert "actor=service:watchdog" in blob and "action=watchdog.check_health" in blob


def test_watchdog_loop_without_healed_services_does_not_announce(monkeypatch):
    """Lista vazia real (não a string '[]' que o CP devolveria em .output)
    continua sendo tratada como falsy — prova de que a captura preserva o tipo."""
    _mock_common(monkeypatch)
    announced: list = []
    monkeypatch.setattr(main_module, "_announce", lambda msg: announced.append(msg))
    monkeypatch.setattr(main_module, "check_and_heal", lambda: [])
    operating_mode.set_operating_mode("real")

    _one_iteration(monkeypatch, main_module.watchdog_loop)

    assert announced == []


def test_risk_sweep_loop_uses_service_watchdog_principal_and_announces_expired(monkeypatch):
    _mock_common(monkeypatch)
    announced: list = []
    monkeypatch.setattr(main_module, "_announce", lambda msg: announced.append(msg))
    monkeypatch.setattr(main_module, "sweep_expired", lambda: [42])
    operating_mode.set_operating_mode("real")

    _one_iteration(monkeypatch, main_module.risk_sweep_loop)

    assert announced == ["Ação(ões) pendente(s) expirada(s) sem confirmação: [42]"]
    blob = _audit_blob()
    assert "actor=service:watchdog" in blob and "action=risk.sweep_expired" in blob


def test_risk_sweep_loop_without_expired_does_not_announce(monkeypatch):
    _mock_common(monkeypatch)
    announced: list = []
    monkeypatch.setattr(main_module, "_announce", lambda msg: announced.append(msg))
    monkeypatch.setattr(main_module, "sweep_expired", lambda: [])
    operating_mode.set_operating_mode("real")

    _one_iteration(monkeypatch, main_module.risk_sweep_loop)

    assert announced == []


def test_report_loop_uses_service_watchdog_principal_and_notifies(monkeypatch):
    _mock_common(monkeypatch)
    notified: list = []
    monkeypatch.setattr(main_module, "send_notification", lambda title, body: notified.append((title, body)))
    monkeypatch.setattr(main_module, "generate_summary_report", lambda hours: "resumo fake (teste)")
    operating_mode.set_operating_mode("real")

    _one_iteration(monkeypatch, main_module.report_loop)

    assert len(notified) == 1
    assert "resumo fake (teste)" in notified[0][1]
    blob = _audit_blob()
    assert "actor=service:watchdog" in blob and "action=report.generate" in blob


# ------------------------- 3: DENY não chama o executor real -------------------------

def _force_readonly_watchdog_principal(monkeypatch):
    monkeypatch.setattr(rbac, "SERVICE_WATCHDOG_PRINCIPAL", rbac.Principal("service:watchdog", "readonly"))


def test_audit_checkpoint_loop_deny_never_calls_real_function(monkeypatch):
    _mock_common(monkeypatch)
    _force_readonly_watchdog_principal(monkeypatch)
    calls: list = []
    monkeypatch.setattr(main_module, "create_checkpoint", lambda: calls.append(1) or "não deveria rodar")
    operating_mode.set_operating_mode("real")

    _one_iteration(monkeypatch, main_module.audit_checkpoint_loop)

    assert calls == []


def test_watchdog_loop_deny_never_calls_real_function(monkeypatch):
    _mock_common(monkeypatch)
    _force_readonly_watchdog_principal(monkeypatch)
    calls: list = []
    monkeypatch.setattr(main_module, "check_and_heal", lambda: calls.append(1) or [])
    operating_mode.set_operating_mode("real")

    _one_iteration(monkeypatch, main_module.watchdog_loop)

    assert calls == []


def test_risk_sweep_loop_deny_never_calls_real_function(monkeypatch):
    _mock_common(monkeypatch)
    _force_readonly_watchdog_principal(monkeypatch)
    calls: list = []
    monkeypatch.setattr(main_module, "sweep_expired", lambda: calls.append(1) or [])
    operating_mode.set_operating_mode("real")

    _one_iteration(monkeypatch, main_module.risk_sweep_loop)

    assert calls == []


def test_report_loop_deny_never_calls_real_function(monkeypatch):
    _mock_common(monkeypatch)
    _force_readonly_watchdog_principal(monkeypatch)
    calls: list = []
    monkeypatch.setattr(main_module, "generate_summary_report", lambda hours: calls.append(1) or "não deveria rodar")
    operating_mode.set_operating_mode("real")

    _one_iteration(monkeypatch, main_module.report_loop)

    assert calls == []


def test_deny_decision_at_policy_level_for_readonly_watchdog():
    """Prova direta (sem depender do loop) de que o papel readonly não tem
    nenhuma das 4 permissões novas — a policy nega, não é coincidência dos
    mocks."""
    from core import control_plane as cp
    for action_type in (
        "risk.sweep_expired", "audit.checkpoint", "watchdog.check_health", "report.generate",
    ):
        with cp.principal_context(rbac.Principal("service:watchdog", "readonly")):
            dec = cp.evaluate(cp.make_request(action_type))
        assert dec.decision is Decision.DENY, action_type


# ------------------------- 4: DRY_RUN_ONLY (lab) não chama o executor real -------------------------

def test_audit_checkpoint_loop_lab_mode_no_real_call(monkeypatch):
    _mock_common(monkeypatch)
    calls: list = []
    monkeypatch.setattr(main_module, "create_checkpoint", lambda: calls.append(1) or "não deveria rodar")
    operating_mode.set_operating_mode("lab")

    _one_iteration(monkeypatch, main_module.audit_checkpoint_loop)

    assert calls == []


def test_watchdog_loop_lab_mode_no_real_call(monkeypatch):
    _mock_common(monkeypatch)
    calls: list = []
    monkeypatch.setattr(main_module, "check_and_heal", lambda: calls.append(1) or [])
    operating_mode.set_operating_mode("lab")

    _one_iteration(monkeypatch, main_module.watchdog_loop)

    assert calls == []


def test_risk_sweep_loop_replay_mode_no_real_call(monkeypatch):
    _mock_common(monkeypatch)
    calls: list = []
    monkeypatch.setattr(main_module, "sweep_expired", lambda: calls.append(1) or [])
    operating_mode.set_operating_mode("replay")

    _one_iteration(monkeypatch, main_module.risk_sweep_loop)

    assert calls == []


def test_report_loop_still_runs_in_lab_mode_because_changes_state_is_false(monkeypatch):
    """report.generate tem changes_state=False deliberado — o cinto de lab/
    replay (que só se aplica a ações que ALTERAM estado) não o afeta; só o
    RBAC protege. Em lab, com o Service Principal padrão (que TEM a
    permissão), o resumo continua sendo gerado e notificado."""
    _mock_common(monkeypatch)
    notified: list = []
    monkeypatch.setattr(main_module, "send_notification", lambda title, body: notified.append((title, body)))
    monkeypatch.setattr(main_module, "generate_summary_report", lambda hours: "resumo em lab (teste)")
    operating_mode.set_operating_mode("lab")

    _one_iteration(monkeypatch, main_module.report_loop)

    assert len(notified) == 1
    assert "resumo em lab (teste)" in notified[0][1]


# ------------------------- 5: admin/service autorizado em modo real chama o executor -------------------------
# (já coberto pelos testes da seção 1 — todos rodam com operating_mode="real"
# e o SERVICE_WATCHDOG_PRINCIPAL padrão, que agora TEM as 4 permissões novas.)


# ------------------------- escopo: loops fora desta fase continuam intocados -------------------------

def test_subscriber_billing_loop_not_touched():
    src = inspect.getsource(main_module.subscriber_billing_loop)
    assert "cp.request_action" not in src and "cp.make_request" not in src


def test_siem_loop_not_touched():
    src = inspect.getsource(main_module.siem_loop)
    assert "cp.request_action" not in src and "cp.make_request" not in src


def test_threat_feed_refresh_loop_not_touched():
    src = inspect.getsource(main_module.threat_feed_refresh_loop)
    assert "cp.request_action" not in src and "cp.make_request" not in src


def test_asset_inventory_loop_not_touched():
    src = inspect.getsource(main_module.asset_inventory_loop)
    assert "cp.request_action" not in src and "cp.make_request" not in src


def test_dns_monitor_loop_not_touched():
    src = inspect.getsource(main_module.dns_monitor_loop)
    assert "cp.request_action" not in src and "cp.make_request" not in src


def test_device_monitor_loop_not_touched():
    src = inspect.getsource(main_module.device_monitor_loop)
    assert "cp.request_action" not in src and "cp.make_request" not in src


def test_monitor_loop_auto_isolate_now_routed_through_cp_since_phase_6o():
    """Até a Fase 6N, monitor_loop já usava SERVICE_MONITOR_PRINCIPAL no
    ask_agent (Fase 5D), mas firewall.block_ip continuava chamado direto —
    não migrado nesta fase (6B). CP-SD Fase 6O fechou esse bypass: o corpo
    de monitor_loop não chama mais firewall.block_ip nem cp.request_action
    diretamente — delega a _monitor_auto_isolate (função-irmã em main.py),
    que faz a chamada real ao Control Plane. Ver
    tests/security/test_monitor_loop_control_plane.py para a cobertura
    completa da Fase 6O."""
    src = inspect.getsource(main_module.monitor_loop)
    assert "firewall.block_ip(" not in src
    assert "_monitor_auto_isolate(" in src
    assert "cp.request_action" not in src and "cp.make_request" not in src  # delega ao helper, não inline


def test_reconcile_loop_check_and_reconcile_still_direct_not_wrapped_by_cp():
    """reconcile_loop já usa SERVICE_RECONCILE_PRINCIPAL no ask_agent (Fase 5B),
    mas check_and_reconcile(auto_reapply=True) continua chamado direto."""
    src = inspect.getsource(main_module.reconcile_loop)
    assert "check_and_reconcile(auto_reapply=True)" in src
    assert "cp.request_action" not in src and "cp.make_request" not in src


def test_no_new_service_principal_constant_introduced():
    """Esta fase (6B) só concede permissões ao papel "service" — nenhum
    novo Principal constante deveria ter sido criado em core/rbac.py NESTA
    fase. CP-SD Fase 6M (posterior) criou deliberadamente 1 Principal novo
    (SERVICE_THREAT_FEED_PRINCIPAL, ver test_threat_feed_lists_control_plane.py)
    — o conjunto abaixo foi atualizado para refletir o estado atual; o
    espírito do teste (nenhum Principal SEM PROPÓSITO/RASTREADO) continua
    valendo."""
    known = {
        rbac.SERVICE_MONITOR_PRINCIPAL, rbac.SERVICE_PROACTIVE_AUDIT_PRINCIPAL,
        rbac.SERVICE_RECONCILE_PRINCIPAL, rbac.SERVICE_BILLING_PRINCIPAL,
        rbac.SERVICE_PLAYBOOK_PRINCIPAL, rbac.SERVICE_HONEYPOT_PRINCIPAL,
        rbac.SERVICE_HONEYTOKEN_PRINCIPAL, rbac.SERVICE_ABUSEIPDB_REPORTER_PRINCIPAL,
        rbac.SERVICE_WATCHDOG_PRINCIPAL, rbac.SERVICE_SIEM_PRINCIPAL,
        rbac.SERVICE_THREAT_FEED_PRINCIPAL,
    }
    all_names = {
        name for name in dir(rbac) if name.startswith("SERVICE_") and name.endswith("_PRINCIPAL")
    }
    assert all_names == {
        "SERVICE_MONITOR_PRINCIPAL", "SERVICE_PROACTIVE_AUDIT_PRINCIPAL",
        "SERVICE_RECONCILE_PRINCIPAL", "SERVICE_BILLING_PRINCIPAL",
        "SERVICE_PLAYBOOK_PRINCIPAL", "SERVICE_HONEYPOT_PRINCIPAL",
        "SERVICE_HONEYTOKEN_PRINCIPAL", "SERVICE_ABUSEIPDB_REPORTER_PRINCIPAL",
        "SERVICE_WATCHDOG_PRINCIPAL", "SERVICE_SIEM_PRINCIPAL",
        "SERVICE_THREAT_FEED_PRINCIPAL",
    }
    assert len(known) == 11


# ------------------------- RBAC: service não virou admin, não recebeu "*" -------------------------

def test_service_role_still_has_no_wildcard_and_is_not_admin():
    perms = rbac.ROLE_PERMISSIONS["service"]
    assert "*" not in perms
    for p in perms:
        assert p != "*"
    assert rbac.SERVICE_WATCHDOG_PRINCIPAL.role == "service"
    assert rbac.SERVICE_WATCHDOG_PRINCIPAL.role != "admin"


def test_service_role_gained_only_the_four_expected_permissions():
    """As permissões humanas (readonly/auditor/soc_analyst) não devem ter
    sido alteradas por esta fase. A checagem do papel "service" é por
    SUBCONJUNTO (não "=="): CP-SD Fase 6D (posterior a esta) acrescentou
    mais 2 permissões (noc.block_subscriber/noc.unblock_subscriber) — o
    conjunto EXATO e atualizado vive em
    test_billing_control_plane.py::test_service_role_full_permission_set_after_phase_6d.
    "noc_operator" também é checado por SUBCONJUNTO: CP-SD Fase 6F (posterior)
    acrescentou "billing.run_cycle.trigger" — o único papel HUMANO alterado
    em todo o arco até agora, necessário para não regredir o uso legítimo de
    POST /api/billing/run (ver test_billing_control_plane.py)."""
    assert {
        "read", "risk.sweep_expired", "audit.checkpoint",
        "watchdog.check_health", "report.generate",
    }.issubset(rbac.ROLE_PERMISSIONS["service"])
    assert rbac.ROLE_PERMISSIONS["readonly"] == {"read"}
    assert rbac.ROLE_PERMISSIONS["auditor"] == {"read", "audit"}
    assert rbac.ROLE_PERMISSIONS["soc_analyst"] == {"read", "audit", "defense.*", "investigate.*"}
    assert {
        "read", "noc.*", "defense.block_ip", "defense.unblock_ip",
    }.issubset(rbac.ROLE_PERMISSIONS["noc_operator"])


def test_new_permissions_not_granted_to_human_roles_via_wildcard():
    for role in ("readonly", "auditor", "soc_analyst", "noc_operator"):
        for perm in (
            "risk.sweep_expired", "audit.checkpoint", "watchdog.check_health", "report.generate",
        ):
            assert not rbac.has_permission(role, perm), f"{role} não deveria ter {perm}"
