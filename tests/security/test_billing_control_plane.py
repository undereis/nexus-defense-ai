"""CP-SD Fase 6D — block_subscriber/unblock_subscriber (tools/billing.py)
governados pelo Control Plane antes de tocar o Mikrotik real.

Escopo desta fase (ver docstring de tools/billing.py:block_subscriber e
CLAUDE.md): só a MUTAÇÃO REAL do billing (as duas funções que chamam
mikrotik.block_subscriber_ip/unblock_subscriber_ip) passa a ser gateada por
`cp.request_action` (RBAC + cinto de modo lab/replay). `run_billing_cycle`
como EVENTO DE DISPARO, o endpoint REST `/api/billing/run`, o mapeamento em
`tools/risk.py:_TOOL_ACTION_MAP` e o cinto de modo dentro de
`tools/mikrotik.py` continuam FORA de escopo (ver relatório da Fase 6C) —
esta suíte não declara nenhum desses caminhos como resolvido.

Nenhum Mikrotik/rede real: `billing.mikrotik.block_subscriber_ip`/
`unblock_subscriber_ip` são sempre mockados por `fake_mikrotik`. DB sempre
temporário (fixture autouse `clean_db` de tests/security/conftest.py).
"""

import inspect

import pytest

import database.db as db_module
from core import control_plane as cp
from core import operating_mode, rbac
from tools import billing, infrastructure


@pytest.fixture
def fake_mikrotik(monkeypatch):
    calls = {"block": [], "unblock": []}

    def fake_block(ip):
        calls["block"].append(ip)
        return f"IP {ip} bloqueado (forward/drop)."

    def fake_unblock(ip):
        calls["unblock"].append(ip)
        return f"IP {ip} desbloqueado (1 regra(s) removida(s))."

    monkeypatch.setattr(billing.mikrotik, "block_subscriber_ip", fake_block)
    monkeypatch.setattr(billing.mikrotik, "unblock_subscriber_ip", fake_unblock)
    return calls


def _cp_decision_events() -> list[str]:
    """Linhas de auditoria que só existem se o Control Plane foi
    efetivamente consultado (cp.evaluate audita incondicionalmente, mesmo em
    DENY/DRY_RUN_ONLY) — ausência delas prova que o CP nunca foi chamado."""
    with db_module.get_conn() as conn:
        rows = conn.execute(
            "SELECT detail FROM events WHERE event_type IN "
            "('control_plane_decision', 'control_plane_executed')"
        ).fetchall()
    return [r[0] for r in rows]


def _subscriber_actions(sid: str) -> list[str]:
    return [a[1] for a in db_module.list_subscriber_actions(sid)]


# ------------------------- 1/2: modo real + RBAC ok -> Mikrotik chamado via CP -------------------------

def test_block_subscriber_real_mode_allowed_calls_mikrotik_via_cp(fake_mikrotik):
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="pendente", days_overdue=10)

    ok, detail = billing.block_subscriber({"subscriber_id": "c1", "ip_address": "203.0.113.5",
                                            "days_overdue": 10})

    assert ok is True
    assert fake_mikrotik["block"] == ["203.0.113.5"]
    assert "OK" in detail
    assert db_module.get_subscriber("c1")[5] == "bloqueado_inadimplencia"
    assert "bloqueado" in _subscriber_actions("c1")
    blob = " ".join(_cp_decision_events())
    assert "action=block_subscriber" in blob
    assert "actor=service:billing" in blob
    assert "role=service" in blob


def test_unblock_subscriber_real_mode_allowed_calls_mikrotik_via_cp(fake_mikrotik):
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="em_dia")
    db_module.set_subscriber_status("c1", "bloqueado_inadimplencia")

    ok, detail = billing.unblock_subscriber({"subscriber_id": "c1", "ip_address": "203.0.113.5"})

    assert ok is True
    assert fake_mikrotik["unblock"] == ["203.0.113.5"]
    assert "OK" in detail
    assert db_module.get_subscriber("c1")[5] == "ativo"
    assert "desbloqueado" in _subscriber_actions("c1")
    blob = " ".join(_cp_decision_events())
    assert "action=unblock_subscriber" in blob
    assert "actor=service:billing" in blob


# ------------------------- 3/4: DENY por RBAC não chama Mikrotik -------------------------

def _force_readonly_billing_principal(monkeypatch):
    """Simula um papel sem a permissão nova, sem mexer no papel 'service'
    real nem nos outros testes — só o SERVICE_BILLING_PRINCIPAL é trocado
    temporariamente por um Principal com papel 'readonly' (só 'read')."""
    monkeypatch.setattr(rbac, "SERVICE_BILLING_PRINCIPAL", rbac.Principal("service:billing", "readonly"))


def test_block_subscriber_deny_by_rbac_does_not_call_mikrotik(fake_mikrotik, monkeypatch):
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="pendente", days_overdue=10)
    _force_readonly_billing_principal(monkeypatch)

    ok, detail = billing.block_subscriber({"subscriber_id": "c1", "ip_address": "203.0.113.5",
                                            "days_overdue": 10})

    assert ok is False
    assert fake_mikrotik["block"] == []
    assert "NEGADO" in detail
    assert db_module.get_subscriber("c1")[5] == "ativo"  # status intacto
    assert "bloqueio_negado_cp" in _subscriber_actions("c1")


def test_unblock_subscriber_deny_by_rbac_does_not_call_mikrotik(fake_mikrotik, monkeypatch):
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="em_dia")
    db_module.set_subscriber_status("c1", "bloqueado_inadimplencia")
    _force_readonly_billing_principal(monkeypatch)

    ok, detail = billing.unblock_subscriber({"subscriber_id": "c1", "ip_address": "203.0.113.5"})

    assert ok is False
    assert fake_mikrotik["unblock"] == []
    assert "NEGADO" in detail
    assert db_module.get_subscriber("c1")[5] == "bloqueado_inadimplencia"  # status intacto
    assert "desbloqueio_negado_cp" in _subscriber_actions("c1")


# ------------------------- correção pós-review: nunca sobrescrever Principal real -------------------------
# Achado do operador: a versão original desta fase entrava incondicionalmente
# em cp.principal_context(SERVICE_BILLING_PRINCIPAL) dentro de block/unblock,
# o que SOBRESCREVIA qualquer Principal real já propagado (chat/agente/Slack/
# Telegram/REST) — um chamador sem noc.block_subscriber/noc.unblock_subscriber
# (ex.: readonly) poderia "virar" service:billing só por invocar a tool, uma
# elevação de privilégio. Corrigido em tools/billing.py:_billing_principal_context:
# só assume o Service Principal quando cp.get_current_principal() é None.

def test_block_subscriber_without_context_principal_uses_service_billing(fake_mikrotik):
    """Sem Principal no ContextVar (caso do subscriber_billing_loop, que não
    tem identidade própria): a auditoria usa service:billing/service — este
    é o caminho automático que esta fase deveria proteger desde o início."""
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="pendente", days_overdue=10)
    assert cp.get_current_principal() is None

    ok, _detail = billing.block_subscriber({"subscriber_id": "c1", "ip_address": "203.0.113.5",
                                             "days_overdue": 10})

    assert ok is True
    assert fake_mikrotik["block"] == ["203.0.113.5"]
    blob = " ".join(_cp_decision_events())
    assert "actor=service:billing" in blob
    assert "role=service" in blob


def test_block_subscriber_inside_noc_operator_context_uses_real_identity_not_service(fake_mikrotik):
    """Com um Principal real já no contexto (ex.: /chat, Slack, Telegram, ou
    o próprio caminho REST individual — ver noc_api.block_subscriber),
    block_subscriber NÃO pode sobrescrevê-lo para service:billing. Serve
    também de proxy para o caminho REST individual (instrução 5): noc_operator
    já tem "noc.*" (cobre noc.block_subscriber), então a ação é ALLOW, mas
    com a identidade REAL na auditoria, nunca service:billing."""
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="pendente", days_overdue=10)
    noc_principal = rbac.Principal("user:ana", "noc_operator")

    with cp.principal_context(noc_principal):
        ok, _detail = billing.block_subscriber({"subscriber_id": "c1", "ip_address": "203.0.113.5",
                                                 "days_overdue": 10})

    assert ok is True
    assert fake_mikrotik["block"] == ["203.0.113.5"]
    blob = " ".join(_cp_decision_events())
    assert "actor=user:ana" in blob
    assert "role=noc_operator" in blob
    assert "actor=service:billing" not in blob


def test_unblock_subscriber_inside_noc_operator_context_uses_real_identity_not_service(fake_mikrotik):
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="em_dia")
    db_module.set_subscriber_status("c1", "bloqueado_inadimplencia")
    noc_principal = rbac.Principal("user:ana", "noc_operator")

    with cp.principal_context(noc_principal):
        ok, _detail = billing.unblock_subscriber({"subscriber_id": "c1", "ip_address": "203.0.113.5"})

    assert ok is True
    assert fake_mikrotik["unblock"] == ["203.0.113.5"]
    blob = " ".join(_cp_decision_events())
    assert "actor=user:ana" in blob
    assert "role=noc_operator" in blob
    assert "actor=service:billing" not in blob


def test_block_subscriber_inside_readonly_context_denies_and_does_not_escalate(fake_mikrotik):
    """O caso crítico do achado: um chamador readonly (ex.: usuário sem
    permissão via chat) NÃO pode ter a chamada reclassificada como
    service:billing só porque a função interna tem acesso ao Service
    Principal. Deve dar DENY com a identidade REAL (readonly), nunca ALLOW
    como serviço."""
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="pendente", days_overdue=10)
    readonly_principal = rbac.Principal("user:bob", "readonly")

    with cp.principal_context(readonly_principal):
        ok, detail = billing.block_subscriber({"subscriber_id": "c1", "ip_address": "203.0.113.5",
                                                "days_overdue": 10})

    assert ok is False
    assert fake_mikrotik["block"] == []
    assert "NEGADO" in detail
    assert db_module.get_subscriber("c1")[5] == "ativo"
    blob = " ".join(_cp_decision_events())
    assert "actor=user:bob" in blob
    assert "role=readonly" in blob
    assert "actor=service:billing" not in blob


def test_unblock_subscriber_inside_readonly_context_denies_and_does_not_escalate(fake_mikrotik):
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="em_dia")
    db_module.set_subscriber_status("c1", "bloqueado_inadimplencia")
    readonly_principal = rbac.Principal("user:bob", "readonly")

    with cp.principal_context(readonly_principal):
        ok, detail = billing.unblock_subscriber({"subscriber_id": "c1", "ip_address": "203.0.113.5"})

    assert ok is False
    assert fake_mikrotik["unblock"] == []
    assert "NEGADO" in detail
    assert db_module.get_subscriber("c1")[5] == "bloqueado_inadimplencia"
    blob = " ".join(_cp_decision_events())
    assert "actor=user:bob" in blob
    assert "actor=service:billing" not in blob


def test_agent_tool_block_subscriber_under_readonly_context_does_not_escalate(fake_mikrotik):
    """Reproduz o cenário de risco descrito pelo operador: um usuário
    readonly no /chat aciona a tool do agente (que chama
    billing.block_subscriber_by_id DIRETO, sem gate próprio — achado da
    Fase 6C). Como ask_agent seta o ContextVar com o Principal real durante
    toda a invocação, a chamada interna a block_subscriber NÃO pode se
    elevar para service:billing."""
    import agents.nexus_agent as agent_module

    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="pendente", days_overdue=10)
    readonly_principal = rbac.Principal("chat:readonly-user", "readonly")

    with cp.principal_context(readonly_principal):
        detail = agent_module.block_subscriber.func("c1")

    assert fake_mikrotik["block"] == []
    assert "NEGADO" in detail
    assert db_module.get_subscriber("c1")[5] == "ativo"
    blob = " ".join(_cp_decision_events())
    assert "actor=service:billing" not in blob


def test_agent_tool_run_billing_cycle_now_under_readonly_context_does_not_escalate(fake_mikrotik):
    """Mesmo cenário para run_billing_cycle_now(dry_run=False): mesmo que o
    disparo do ciclo em si não seja gateado nesta fase (fora de escopo — ver
    Fase 6C), cada bloqueio individual dentro dele passa por
    block_subscriber, que agora respeita a identidade readonly propagada e
    nega, em vez de se elevar para service:billing."""
    import agents.nexus_agent as agent_module

    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="pendente", days_overdue=10)
    readonly_principal = rbac.Principal("chat:readonly-user", "readonly")

    with cp.principal_context(readonly_principal):
        agent_module.run_billing_cycle_now.func(dry_run=False)

    assert fake_mikrotik["block"] == []
    assert db_module.get_subscriber("c1")[5] == "ativo"


# ------------------------- 5/6: lab/replay -> DRY_RUN_ONLY, nunca chama Mikrotik -------------------------

def test_block_subscriber_lab_mode_is_dry_run_does_not_call_mikrotik(fake_mikrotik):
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="pendente", days_overdue=10)
    operating_mode.set_operating_mode("lab")

    ok, detail = billing.block_subscriber({"subscriber_id": "c1", "ip_address": "203.0.113.5",
                                            "days_overdue": 10})

    assert ok is False
    assert fake_mikrotik["block"] == []
    assert "DRY-RUN" in detail
    assert "lab" in detail
    assert db_module.get_subscriber("c1")[5] == "ativo"  # nunca mudou de status
    assert "bloqueio_dry_run" in _subscriber_actions("c1")


def test_unblock_subscriber_replay_mode_is_dry_run_does_not_call_mikrotik(fake_mikrotik):
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="em_dia")
    db_module.set_subscriber_status("c1", "bloqueado_inadimplencia")
    operating_mode.set_operating_mode("replay")

    ok, detail = billing.unblock_subscriber({"subscriber_id": "c1", "ip_address": "203.0.113.5"})

    assert ok is False
    assert fake_mikrotik["unblock"] == []
    assert "DRY-RUN" in detail
    assert "replay" in detail
    assert db_module.get_subscriber("c1")[5] == "bloqueado_inadimplencia"  # nunca reativou
    assert "desbloqueio_dry_run" in _subscriber_actions("c1")


# ------------------------- 7: _is_safe_to_block roda ANTES do Control Plane -------------------------

def test_is_safe_to_block_runs_before_control_plane_for_critical_ip(fake_mikrotik):
    infrastructure.register_ip_block("203.0.113.0/24", "Bloco crítico", is_critical=True)
    db_module.add_subscriber("infra1", "203.0.113.5", invoice_status="pendente", days_overdue=9)

    ok, detail = billing.block_subscriber({"subscriber_id": "infra1", "ip_address": "203.0.113.5",
                                            "days_overdue": 9})

    assert ok is False
    assert fake_mikrotik["block"] == []
    assert "RECUSADO" in detail
    assert db_module.get_subscriber("infra1")[5] == "ativo"
    assert "bloqueio_recusado" in _subscriber_actions("infra1")
    # a trava de infra nunca deixa o fluxo chegar a montar um ActionRequest —
    # nenhum evento de decisão do Control Plane é gerado para este IP.
    assert _cp_decision_events() == []


def test_is_safe_to_block_loopback_runs_before_control_plane(fake_mikrotik):
    ok, detail = billing.block_subscriber({"subscriber_id": "loop1", "ip_address": "127.0.0.1",
                                            "days_overdue": 9})
    assert ok is False
    assert fake_mikrotik["block"] == []
    assert _cp_decision_events() == []


# ------------------------- 8: run_billing_cycle(dry_run=True) nunca chama CP/Mikrotik -------------------------

def test_run_billing_cycle_dry_run_never_touches_cp_or_mikrotik(fake_mikrotik):
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="pendente", days_overdue=10)

    summary = billing.run_billing_cycle(min_days=5, dry_run=True)

    assert "DRY-RUN" in summary
    assert fake_mikrotik["block"] == []
    assert fake_mikrotik["unblock"] == []
    assert db_module.get_subscriber("c1")[5] == "ativo"
    assert _cp_decision_events() == []


# ------------------------- 9: cap de lote aborta ANTES de qualquer CP/Mikrotik -------------------------

def test_cap_aborts_before_cp_or_mikrotik(fake_mikrotik, monkeypatch):
    monkeypatch.setattr(billing.notify, "send_notification", lambda *a, **k: True)
    for i in range(6):
        db_module.add_subscriber(f"c{i}", f"203.0.113.{10 + i}",
                                 invoice_status="pendente", days_overdue=9)

    summary = billing.run_billing_cycle(min_days=5, max_batch=3)

    assert "ABORTADO POR SEGURANÇA" in summary
    assert fake_mikrotik["block"] == []
    assert all(db_module.get_subscriber(f"c{i}")[5] == "ativo" for i in range(6))
    assert _cp_decision_events() == []


# ------------------------- 10: block_subscriber_by_id/unblock_subscriber_by_id são governados -------------------------

def test_block_subscriber_by_id_is_governed(fake_mikrotik):
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="pendente", days_overdue=10)

    detail = billing.block_subscriber_by_id("c1")

    assert fake_mikrotik["block"] == ["203.0.113.5"]
    assert "OK" in detail
    assert db_module.get_subscriber("c1")[5] == "bloqueado_inadimplencia"


def test_unblock_subscriber_by_id_is_governed(fake_mikrotik):
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="em_dia")
    db_module.set_subscriber_status("c1", "bloqueado_inadimplencia")

    detail = billing.unblock_subscriber_by_id("c1")

    assert fake_mikrotik["unblock"] == ["203.0.113.5"]
    assert "OK" in detail
    assert db_module.get_subscriber("c1")[5] == "ativo"


def test_block_subscriber_by_id_denied_by_rbac_does_not_call_mikrotik(fake_mikrotik, monkeypatch):
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="pendente", days_overdue=10)
    _force_readonly_billing_principal(monkeypatch)

    detail = billing.block_subscriber_by_id("c1")

    assert fake_mikrotik["block"] == []
    assert "NEGADO" in detail


# ------------------------- 11: caminho REST individual (já usava CP) continua compatível -------------------------

def test_noc_api_individual_block_still_works_end_to_end(fake_mikrotik):
    """noc_api.block_subscriber já passava pelo CP na camada REST (Fase 8 /
    integração anterior), delegando a billing.block_subscriber_by_id. Com a
    Fase 6D, essa chamada agora é DUPLAMENTE gateada (camada REST + camada
    interna do billing) — o contrato {"message", "decision", "status"} e o
    resultado final não podem quebrar."""
    from tools import noc_api

    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="pendente", days_overdue=10)

    result = noc_api.block_subscriber("c1", reason="teste REST")

    assert fake_mikrotik["block"] == ["203.0.113.5"]
    assert "message" in result and "decision" in result and "status" in result
    assert db_module.get_subscriber("c1")[5] == "bloqueado_inadimplencia"


# ------------------------- 12: tools do agente ganham a proteção por delegação (estático) -------------------------

def test_agent_tools_still_delegate_to_governed_billing_functions():
    """Fase 6D NÃO altera agents/nexus_agent.py (fora de escopo). As tools do
    agente (run_billing_cycle_now/block_subscriber/unblock_subscriber)
    continuam delegando diretamente a billing.run_billing_cycle/
    block_subscriber_by_id/unblock_subscriber_by_id; como essas funções agora
    passam pelo Control Plane por dentro, o agente ganha a mesma proteção sem
    editar aquele arquivo. Um teste de integração completo do agente
    (invocação real via @tool/StructuredTool) fica para uma fase futura --
    aqui confirmamos estaticamente que a delegação não mudou."""
    import agents.nexus_agent as agent_module

    run_src = inspect.getsource(agent_module.run_billing_cycle_now.func)
    block_src = inspect.getsource(agent_module.block_subscriber.func)
    unblock_src = inspect.getsource(agent_module.unblock_subscriber.func)
    assert "billing.run_billing_cycle(" in run_src
    assert "billing.block_subscriber_by_id(" in block_src
    assert "billing.unblock_subscriber_by_id(" in unblock_src


# ------------------------- 17/18: RBAC do papel "service" -------------------------

def test_service_role_gained_only_the_two_billing_permissions():
    perms = rbac.ROLE_PERMISSIONS["service"]
    assert "noc.block_subscriber" in perms
    assert "noc.unblock_subscriber" in perms
    assert "noc.billing" not in perms
    assert "noc.*" not in perms
    assert "*" not in perms


def test_service_billing_principal_role_is_service_not_admin():
    assert rbac.SERVICE_BILLING_PRINCIPAL.role == "service"
    assert rbac.SERVICE_BILLING_PRINCIPAL.role != "admin"
    assert rbac.SERVICE_BILLING_PRINCIPAL.actor == "service:billing"


# ------------------------- 19: papéis humanos inalterados -------------------------

def test_human_roles_unchanged_after_phase_6d():
    assert rbac.ROLE_PERMISSIONS["admin"] == {"*"}
    assert rbac.ROLE_PERMISSIONS["soc_analyst"] == {"read", "audit", "defense.*", "investigate.*"}
    assert rbac.ROLE_PERMISSIONS["noc_operator"] == {
        "read", "noc.*", "defense.block_ip", "defense.unblock_ip",
    }
    assert rbac.ROLE_PERMISSIONS["auditor"] == {"read", "audit"}
    assert rbac.ROLE_PERMISSIONS["readonly"] == {"read"}


def test_service_role_full_permission_set_after_phase_6d():
    assert rbac.ROLE_PERMISSIONS["service"] == {
        "read",
        "risk.sweep_expired", "audit.checkpoint", "watchdog.check_health", "report.generate",
        "noc.block_subscriber", "noc.unblock_subscriber",
    }
