"""CP-SD Fase 6R — fecha os 4 call-sites diretos remanescentes de
firewall.block_ip, roteando cada subsistema de defesa pelo Control Plane:

  - tools/honeypot.py:_isolate                 -> "honeypot.auto_isolate"
  - tools/honeytokens.py:handle_canary_trigger -> "honeytoken.auto_isolate"
  - tools/playbook.py:evaluate_and_respond(N2) -> "playbook.auto_isolate"
  - tools/reconcile.py:check_and_reconcile     -> "reconcile.reapply_block"

Cada um passa por RBAC + trava dura de infra crítica (asset_registry) + cinto
de modo (lab/replay -> DRY_RUN_ONLY, nunca chama firewall.block_ip) + auditoria,
ANTES de qualquer bloqueio real. Os guards locais pré-existentes (honeypot
_is_safe_to_isolate, honeytoken _is_loopback) continuam valendo ANTES do CP
(defesa em profundidade) — nunca removidos.

Nenhum efeito real: firewall.block_ip é sempre trocado por um fake local; o
backstop autouse de tests/security/conftest.py bloqueia subprocess/rede real.
DB sempre temporário (fixture autouse clean_db).

O call-site de MAIOR risco é o playbook: sem esta fase, um atacante que forjasse
como origem um IP da própria infraestrutura poderia, com PLAYBOOK_AUTO_LEVEL
alto, fazer o Nexus auto-bloquear a si mesmo — o teste
test_playbook_critical_infra_hard_denied_no_block prova que a trava dura agora
barra exatamente isso.
"""

import pytest

import database.db as db_module
from core import control_plane as cp
from core import operating_mode
from core import rbac


@pytest.fixture(autouse=True)
def _reset_operating_mode():
    """Isola o modo operacional entre testes (é estado de processo)."""
    original = operating_mode.get_operating_mode()
    yield
    operating_mode.set_operating_mode(original)


def _cp_decision_events() -> list[str]:
    """Linhas de auditoria que só existem se o Control Plane foi efetivamente
    consultado — ausência delas prova que nenhum ActionRequest foi montado."""
    with db_module.get_conn() as conn:
        rows = conn.execute(
            "SELECT detail FROM events WHERE event_type IN "
            "('control_plane_decision', 'control_plane_executed')"
        ).fetchall()
    return [r[0] for r in rows]


def _code_only(fn) -> str:
    """Fonte da função SEM comentários nem docstring — via AST (ast.unparse não
    reemite comentários; a docstring é removida explicitamente). Evita falso
    positivo nas travas estruturais quando o TEXTO explicativo menciona
    SERVICE_/principal_context sem que o CÓDIGO os use."""
    import ast
    import inspect
    import textwrap

    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    func = tree.body[0]
    if (func.body and isinstance(func.body[0], ast.Expr)
            and isinstance(func.body[0].value, ast.Constant)
            and isinstance(func.body[0].value.value, str)):
        func.body = func.body[1:]
    return ast.unparse(tree)


# Contexto de serviço que o ENTRYPOINT confiável instala; nos testes de
# comportamento nós o simulamos explicitamente (o entrypoint real — listener/
# loop — é validado à parte pelos testes estruturais "..._installs_service_context").
_SVC = {
    "honeypot": rbac.SERVICE_HONEYPOT_PRINCIPAL,
    "honeytoken": rbac.SERVICE_HONEYTOKEN_PRINCIPAL,
    "playbook": rbac.SERVICE_PLAYBOOK_PRINCIPAL,
    "reconcile": rbac.SERVICE_RECONCILE_PRINCIPAL,
}


# =========================== honeypot._isolate ===========================

def test_honeypot_isolate_under_service_context_blocks(monkeypatch):
    """Sob a identidade que o entrypoint confiável (listener) instala, o
    isolamento executa e é auditado como service:honeypot."""
    from tools import honeypot

    blocked = []
    monkeypatch.setattr(honeypot.firewall, "block_ip",
                        lambda ip, reason: blocked.append(ip) or f"IP {ip} bloqueado.")
    monkeypatch.setattr(honeypot, "record_confirmed_isolation", lambda *a, **k: None)

    with cp.principal_context(_SVC["honeypot"]):
        honeypot._isolate("203.0.113.50", 2222, "ssh")

    assert blocked == ["203.0.113.50"]
    blob = " ".join(_cp_decision_events())
    assert "action=honeypot.auto_isolate" in blob
    assert "actor=service:honeypot" in blob
    assert "role=service" in blob


def test_honeypot_isolate_without_context_is_denied(monkeypatch):
    """SEM contexto autenticado, _isolate NÃO se autopromove a service:honeypot —
    o Control Plane nega e o executor (firewall.block_ip) NÃO é chamado."""
    from tools import honeypot

    blocked = []
    monkeypatch.setattr(honeypot.firewall, "block_ip", lambda ip, reason: blocked.append(ip))
    monkeypatch.setattr(honeypot, "record_confirmed_isolation", lambda *a, **k: None)

    assert cp.get_current_principal() is None
    honeypot._isolate("203.0.113.50", 2222, "ssh")

    assert blocked == []  # executor não chamado
    blob = " ".join(_cp_decision_events())
    assert "action=honeypot.auto_isolate" in blob
    assert "decision=deny" in blob
    assert "actor=service:honeypot" not in blob  # não se autopromoveu


def test_honeypot_loopback_guard_short_circuits_before_cp(monkeypatch):
    """O guard local _is_safe_to_isolate barra loopback ANTES do Control Plane —
    nem chega a montar ActionRequest (defesa em profundidade preservada), mesmo
    com contexto de serviço."""
    from tools import honeypot

    blocked = []
    monkeypatch.setattr(honeypot.firewall, "block_ip", lambda ip, reason: blocked.append(ip))

    with cp.principal_context(_SVC["honeypot"]):
        honeypot._isolate("127.0.0.1", 2222, "ssh")

    assert blocked == []
    assert _cp_decision_events() == []  # CP nunca consultado


def test_honeypot_lab_mode_is_dry_run_no_block(monkeypatch):
    from tools import honeypot

    operating_mode.set_operating_mode("lab")
    blocked = []
    monkeypatch.setattr(honeypot.firewall, "block_ip", lambda ip, reason: blocked.append(ip))
    monkeypatch.setattr(honeypot, "record_confirmed_isolation", lambda *a, **k: None)

    with cp.principal_context(_SVC["honeypot"]):
        honeypot._isolate("203.0.113.51", 2222, "ssh")

    assert blocked == []  # DRY_RUN_ONLY nunca toca firewall
    blob = " ".join(_cp_decision_events())
    assert "action=honeypot.auto_isolate" in blob
    assert "decision=dry_run_only" in blob


def test_honeypot_listener_installs_service_context():
    """Item 4: o listener _handle_connection é o entrypoint confiável que instala
    SERVICE_HONEYPOT explicitamente antes do caminho governado."""
    import inspect

    from tools import honeypot

    src = inspect.getsource(honeypot._handle_connection)
    assert "principal_context(rbac.SERVICE_HONEYPOT_PRINCIPAL)" in src
    assert "_process_hit(" in src


# ===================== honeytokens.handle_canary_trigger =====================

def _plant_token(token_id: str = "tok-6r") -> str:
    """Planta um honeytoken direto no DB (sem depender de CANARY_BASE_URL, que
    plant_decoy_file exige) — o que importa aqui é o caminho de DISPARO."""
    db_module.plant_honeytoken(token_id, "aws_credentials", "/tmp/isca")
    return token_id


def test_honeytoken_isolate_under_service_context_blocks(monkeypatch):
    from tools import honeytokens

    token_id = _plant_token()
    blocked = []
    monkeypatch.setattr(honeytokens.firewall, "block_ip",
                        lambda ip, reason: blocked.append(ip) or "ok")
    monkeypatch.setattr(honeytokens, "record_confirmed_isolation", lambda *a, **k: None)

    with cp.principal_context(_SVC["honeytoken"]):
        honeytokens.handle_canary_trigger(token_id, "198.51.100.7", "teste")

    assert blocked == ["198.51.100.7"]
    blob = " ".join(_cp_decision_events())
    assert "action=honeytoken.auto_isolate" in blob
    assert "actor=service:honeytoken" in blob


def test_honeytoken_isolate_without_context_is_denied(monkeypatch):
    """SEM contexto autenticado, o isolamento por honeytoken é NEGADO e
    firewall.block_ip NÃO é chamado — sem autopromoção."""
    from tools import honeytokens

    token_id = _plant_token()
    blocked = []
    monkeypatch.setattr(honeytokens.firewall, "block_ip", lambda ip, reason: blocked.append(ip))
    monkeypatch.setattr(honeytokens, "record_confirmed_isolation", lambda *a, **k: None)

    assert cp.get_current_principal() is None
    honeytokens.handle_canary_trigger(token_id, "198.51.100.7", "teste")

    assert blocked == []
    blob = " ".join(_cp_decision_events())
    assert "action=honeytoken.auto_isolate" in blob
    assert "decision=deny" in blob
    assert "actor=service:honeytoken" not in blob


def test_honeytoken_loopback_guard_short_circuits_before_cp(monkeypatch):
    from tools import honeytokens

    token_id = _plant_token()
    blocked = []
    monkeypatch.setattr(honeytokens.firewall, "block_ip", lambda ip, reason: blocked.append(ip))

    with cp.principal_context(_SVC["honeytoken"]):
        honeytokens.handle_canary_trigger(token_id, "127.0.0.1", "teste-local")

    assert blocked == []
    assert _cp_decision_events() == []


def test_honeytoken_lab_mode_is_dry_run_no_block(monkeypatch):
    from tools import honeytokens

    token_id = _plant_token()
    operating_mode.set_operating_mode("replay")
    blocked = []
    monkeypatch.setattr(honeytokens.firewall, "block_ip", lambda ip, reason: blocked.append(ip))
    monkeypatch.setattr(honeytokens, "record_confirmed_isolation", lambda *a, **k: None)

    with cp.principal_context(_SVC["honeytoken"]):
        honeytokens.handle_canary_trigger(token_id, "198.51.100.9", "teste")

    assert blocked == []
    blob = " ".join(_cp_decision_events())
    assert "decision=dry_run_only" in blob


def test_honeytoken_canary_listener_installs_service_context():
    """Item 4: o listener do canário _handle_canary_connection instala
    SERVICE_HONEYTOKEN explicitamente antes de handle_canary_trigger."""
    import inspect

    from tools import honeytokens

    src = inspect.getsource(honeytokens._handle_canary_connection)
    assert "principal_context(rbac.SERVICE_HONEYTOKEN_PRINCIPAL)" in src
    assert "handle_canary_trigger(" in src


# ===================== playbook.evaluate_and_respond (N2) =====================

@pytest.fixture
def playbook_ready(monkeypatch):
    from tools import playbook

    monkeypatch.setattr(playbook, "PLAYBOOK_AUTO_LEVEL", 2)
    monkeypatch.setattr(playbook.firewall, "rate_limit_ip", lambda ip, **kw: "throttled")
    monkeypatch.setattr(playbook, "record_confirmed_isolation", lambda *a, **k: None)
    return playbook


def test_playbook_level2_under_service_context_blocks(playbook_ready, monkeypatch):
    """A LÓGICA de nível 2 (throttle + block) sob a identidade de serviço
    autorizada. NÃO existe entrypoint automático em produção que instale
    service:playbook — ver test_playbook_has_no_automatic_service_entrypoint e
    a consequência documentada; este teste exercita o executor sob autorização."""
    playbook = playbook_ready
    blocked = []
    monkeypatch.setattr(playbook.firewall, "block_ip", lambda ip, **kw: blocked.append(ip) or "blocked")

    with cp.principal_context(_SVC["playbook"]):
        playbook.evaluate_and_respond("1.2.3.4", "honeypot_trap")

    assert blocked == ["1.2.3.4"]
    blob = " ".join(_cp_decision_events())
    assert "action=playbook.auto_isolate" in blob
    assert "actor=service:playbook" in blob


def test_playbook_human_call_throttles_but_isolation_denied(playbook_ready, monkeypatch):
    """CONSEQUÊNCIA DOCUMENTADA (comportamento anterior x atual): a tool humana
    evaluate_threat_playbook, com PLAYBOOK_AUTO_LEVEL=2, ANTES auto-isolava no
    nível 2. AGORA, sob identidade humana (não service:playbook), o nível 2 é
    NEGADO: o throttle (nível 1) ainda ocorre, o firewall NÃO é tocado, e o
    relatório indica o nível 2 como NÃO executado (nunca finge sucesso)."""
    playbook = playbook_ready
    throttled, blocked = [], []
    monkeypatch.setattr(playbook.firewall, "rate_limit_ip",
                        lambda ip, **kw: throttled.append(ip) or "throttled")
    monkeypatch.setattr(playbook.firewall, "block_ip", lambda ip, **kw: blocked.append(ip) or "blocked")

    with cp.principal_context(rbac.Principal("user:root", "admin")):
        report = playbook.evaluate_and_respond("1.2.3.4", "honeypot_trap")

    assert throttled == ["1.2.3.4"]  # nível 1 continua executando
    assert blocked == []             # nível 2 NEGADO — firewall intocado
    assert "NÃO executado" in report  # relatório honesto, sem falso sucesso
    assert "actor=service:playbook" not in " ".join(_cp_decision_events())


def test_playbook_without_context_isolation_denied(playbook_ready, monkeypatch):
    playbook = playbook_ready
    blocked = []
    monkeypatch.setattr(playbook.firewall, "block_ip", lambda ip, **kw: blocked.append(ip) or "blocked")

    assert cp.get_current_principal() is None
    playbook.evaluate_and_respond("1.2.3.4", "honeypot_trap")

    assert blocked == []
    assert "decision=deny" in " ".join(_cp_decision_events())


def test_playbook_critical_infra_hard_denied_no_block(playbook_ready, monkeypatch):
    """O achado central da fase: um IP de infraestrutura PRÓPRIA crítica nunca é
    auto-bloqueado pelo playbook — a trava dura de asset_registry.check_target
    (que o playbook NÃO tinha antes da 6R) o barra mesmo sob service:playbook."""
    playbook = playbook_ready
    from tools import asset_registry

    monkeypatch.setattr(asset_registry.infrastructure, "is_critical_ip",
                        lambda ip: ip == "203.0.113.200")
    blocked = []
    monkeypatch.setattr(playbook.firewall, "block_ip", lambda ip, **kw: blocked.append(ip) or "blocked")

    with cp.principal_context(_SVC["playbook"]):
        playbook.evaluate_and_respond("203.0.113.200", "honeypot_trap")

    assert blocked == []  # hard-deny: infra própria nunca sofre auto-bloqueio
    blob = " ".join(_cp_decision_events())
    assert "action=playbook.auto_isolate" in blob
    assert "decision=deny" in blob


def test_playbook_lab_mode_is_dry_run_no_block(playbook_ready, monkeypatch):
    playbook = playbook_ready
    operating_mode.set_operating_mode("lab")
    blocked = []
    monkeypatch.setattr(playbook.firewall, "block_ip", lambda ip, **kw: blocked.append(ip) or "blocked")

    with cp.principal_context(_SVC["playbook"]):
        playbook.evaluate_and_respond("1.2.3.4", "honeypot_trap")

    assert blocked == []
    blob = " ".join(_cp_decision_events())
    assert "decision=dry_run_only" in blob


def test_playbook_auto_level_below_2_never_reaches_cp(monkeypatch):
    """Nível efetivo < 2 (throttle-only) não isola — CP nem é consultado para
    isolamento (comportamento inalterado pela fase)."""
    from tools import playbook

    monkeypatch.setattr(playbook, "PLAYBOOK_AUTO_LEVEL", 1)
    monkeypatch.setattr(playbook.firewall, "rate_limit_ip", lambda ip, **kw: "throttled")
    blocked = []
    monkeypatch.setattr(playbook.firewall, "block_ip", lambda ip, **kw: blocked.append(ip))

    with cp.principal_context(_SVC["playbook"]):
        playbook.evaluate_and_respond("1.2.3.4", "port_scan")

    assert blocked == []
    assert _cp_decision_events() == []


def test_playbook_has_no_automatic_service_entrypoint():
    """Item 4 (declaração explícita): NÃO existe entrypoint automático que
    instale SERVICE_PLAYBOOK — evaluate_and_respond só é chamada pela tool humana
    evaluate_threat_playbook. A função governada NÃO instala Principal e NÃO
    referencia Service Principal (sem autopromoção)."""
    from tools import playbook

    code = _code_only(playbook._playbook_auto_isolate)
    assert "principal_context" not in code
    assert "SERVICE_PLAYBOOK" not in code


# ===================== reconcile.check_and_reconcile =====================

def test_reconcile_reapply_under_service_context(monkeypatch):
    """Sob a identidade instalada pelo entrypoint automático (reconcile_loop), a
    reaplicação executa e é auditada como service:reconcile."""
    from tools import reconcile

    db_module.record_blocked_ip("2.2.2.2", "teste")
    monkeypatch.setattr(reconcile.firewall, "get_actual_blocked_ips", lambda: set())
    monkeypatch.setattr(reconcile.firewall, "block_ip",
                        lambda ip, reason: f"IP {ip} isolado/bloqueado com sucesso.")

    with cp.principal_context(_SVC["reconcile"]):
        result = reconcile.check_and_reconcile(auto_reapply=True)

    assert result.reapplied == ["2.2.2.2"]
    assert result.reapply_errors == {}
    blob = " ".join(_cp_decision_events())
    assert "action=reconcile.reapply_block" in blob
    assert "actor=service:reconcile" in blob


def test_reconcile_without_context_reapply_denied(monkeypatch):
    """CONSEQUÊNCIA DOCUMENTADA: chamada direta a check_and_reconcile sem contexto
    (ex.: tool humana check_firewall_integrity) DETECTA o drift, mas a REAPLICAÇÃO
    é NEGADA — firewall.block_ip NÃO é chamado, o IP vai para reapply_errors com a
    razão do Control Plane, e nada finge sucesso."""
    from tools import reconcile

    db_module.record_blocked_ip("2.2.2.9", "teste")
    monkeypatch.setattr(reconcile.firewall, "get_actual_blocked_ips", lambda: set())
    blocked = []
    monkeypatch.setattr(reconcile.firewall, "block_ip", lambda ip, reason: blocked.append(ip))

    assert cp.get_current_principal() is None
    result = reconcile.check_and_reconcile(auto_reapply=True)

    assert result.has_drift is True          # detecção continua (read-only)
    assert result.missing == ["2.2.2.9"]
    assert blocked == []                      # executor não chamado
    assert result.reapplied == []
    assert "2.2.2.9" in result.reapply_errors  # relatado como falha, não sucesso
    assert "decision=deny" in " ".join(_cp_decision_events())


def test_reconcile_lab_mode_dry_run_not_reapplied(monkeypatch):
    from tools import reconcile

    operating_mode.set_operating_mode("lab")
    db_module.record_blocked_ip("2.2.2.3", "teste")
    monkeypatch.setattr(reconcile.firewall, "get_actual_blocked_ips", lambda: set())
    blocked = []
    monkeypatch.setattr(reconcile.firewall, "block_ip", lambda ip, reason: blocked.append(ip))

    with cp.principal_context(_SVC["reconcile"]):
        result = reconcile.check_and_reconcile(auto_reapply=True)

    assert blocked == []  # DRY_RUN_ONLY nunca reaplica de verdade
    assert result.reapplied == []
    assert "2.2.2.3" in result.reapply_errors
    assert "decision=dry_run_only" in " ".join(_cp_decision_events())


def test_reconcile_critical_infra_hard_denied_not_reapplied(monkeypatch):
    """Defesa em profundidade: mesmo sob service:reconcile e mesmo que um IP
    crítico tivesse entrado indevidamente no conjunto de bloqueados, a
    reaplicação é NEGADA pela trava dura de asset_registry."""
    from tools import asset_registry, reconcile

    monkeypatch.setattr(asset_registry.infrastructure, "is_critical_ip",
                        lambda ip: ip == "203.0.113.201")
    db_module.record_blocked_ip("203.0.113.201", "teste")
    monkeypatch.setattr(reconcile.firewall, "get_actual_blocked_ips", lambda: set())
    blocked = []
    monkeypatch.setattr(reconcile.firewall, "block_ip", lambda ip, reason: blocked.append(ip))

    with cp.principal_context(_SVC["reconcile"]):
        result = reconcile.check_and_reconcile(auto_reapply=True)

    assert blocked == []
    assert result.reapplied == []
    assert "203.0.113.201" in result.reapply_errors


def test_reconcile_no_drift_no_cp_call(monkeypatch):
    """Sem drift (nada faltando), nenhuma reaplicação e nenhum ActionRequest."""
    from tools import reconcile

    db_module.record_blocked_ip("2.2.2.5", "teste")
    monkeypatch.setattr(reconcile.firewall, "get_actual_blocked_ips", lambda: {"2.2.2.5"})

    with cp.principal_context(_SVC["reconcile"]):
        result = reconcile.check_and_reconcile(auto_reapply=True)

    assert result.has_drift is False
    assert _cp_decision_events() == []


def test_reconcile_loop_installs_service_context():
    """Item 4: reconcile_loop (main.py) é o entrypoint automático que instala
    SERVICE_RECONCILE explicitamente antes de check_and_reconcile."""
    import inspect

    import main as main_module

    src = inspect.getsource(main_module.reconcile_loop)
    assert "principal_context(rbac.SERVICE_RECONCILE_PRINCIPAL)" in src
    assert "check_and_reconcile(auto_reapply=True)" in src


# ============ Item 3.8: nenhum módulo reintroduz fallback de identidade ============

def test_no_governed_function_creates_a_service_principal_fallback():
    """Trava estrutural anti-regressão: os helpers _X_principal_context foram
    REMOVIDOS e nenhuma função governada se autopromove (nem instala
    principal_context, nem referencia SERVICE_*). O Service Principal só é
    instalado nos entrypoints confiáveis (testados acima)."""
    from tools import honeypot, honeytokens, playbook, reconcile

    # Os 4 helpers de fallback não existem mais.
    assert not hasattr(honeypot, "_honeypot_principal_context")
    assert not hasattr(honeytokens, "_honeytoken_principal_context")
    assert not hasattr(playbook, "_playbook_principal_context")
    assert not hasattr(reconcile, "_reconcile_principal_context")

    # As funções governadas não instalam contexto nem citam Service Principal
    # (checando o CÓDIGO, não os comentários — via _code_only).
    for fn in (honeypot._isolate, honeytokens._isolate_honeytoken_source,
               playbook._playbook_auto_isolate, reconcile._reconcile_reapply):
        code = _code_only(fn)
        assert "principal_context" not in code, f"{fn.__name__} não pode instalar contexto"
        assert "SERVICE_" not in code, f"{fn.__name__} não pode referenciar Service Principal"


# =========================== ActionSpec ===========================

_ACTIONS_TO_PRINCIPAL = {
    "honeypot.auto_isolate": rbac.SERVICE_HONEYPOT_PRINCIPAL,
    "honeytoken.auto_isolate": rbac.SERVICE_HONEYTOKEN_PRINCIPAL,
    "playbook.auto_isolate": rbac.SERVICE_PLAYBOOK_PRINCIPAL,
    "reconcile.reapply_block": rbac.SERVICE_RECONCILE_PRINCIPAL,
}


def test_action_specs_are_actor_allowlisted_not_role_based():
    from core.policy_engine import ACTION_CATALOG

    for action, principal in _ACTIONS_TO_PRINCIPAL.items():
        spec = ACTION_CATALOG[action]
        # Autorização por PRINCIPAL, não por papel: allowed_actors com o actor
        # exato do subsistema, e required_permission vazio (papel não é a via).
        assert spec.allowed_actors == (principal.actor,)
        assert spec.required_permission == ""
        assert spec.changes_state is True
        assert spec.risk is cp.ActionRisk.MEDIUM
        assert spec.requires_approval is False


# ==================== RBAC: papel "service" NÃO ampliado ====================

def test_service_role_did_NOT_gain_the_four_permissions():
    """A correção da reauditoria: as 4 ações NÃO são permissão do papel
    genérico "service" (senão TODOS os Service Principals as herdariam). Elas
    são gated por PRINCIPAL via allowed_actors."""
    perms = rbac.ROLE_PERMISSIONS["service"]
    for p in ("honeypot.auto_isolate", "honeytoken.auto_isolate",
              "playbook.auto_isolate", "reconcile.reapply_block"):
        assert p not in perms


def test_service_role_exact_set_unchanged_by_6r():
    """Gate FORTE (conjunto exato, não subconjunto): a Fase 6R não pode ter
    ampliado o papel "service" silenciosamente. Este conjunto é idêntico ao
    autoritativo da Fase 6O (test_monitor_loop_control_plane.py)."""
    assert rbac.ROLE_PERMISSIONS["service"] == {
        "read",
        "risk.sweep_expired", "audit.checkpoint", "watchdog.check_health", "report.generate",
        "noc.block_subscriber", "noc.unblock_subscriber",
        "billing.run_cycle.trigger",
        "siem.forward_events",
        "threat_feed.refresh_lists",
        "monitor.auto_isolate",
    }


def test_no_role_grants_the_four_actions_via_rbac():
    """Nenhum papel — nem humano, nem "service", nem admin via wildcard — concede
    as 4 ações por RBAC. A porta é exclusivamente a allowlist de principal.
    (admin tem "*", mas a autorização destas ações NÃO passa por has_permission:
    é gated por allowed_actors no evaluate; ver a matriz por principal abaixo.)"""
    for role in ("admin", "soc_analyst", "noc_operator", "auditor", "readonly", "service"):
        for p in ("honeypot.auto_isolate", "honeytoken.auto_isolate",
                  "playbook.auto_isolate", "reconcile.reapply_block"):
            if role == "admin":
                continue  # "*" casa por RBAC, mas allowed_actors barra no evaluate
            assert not rbac.has_permission(role, p), f"{role} não deveria ter {p} por RBAC"


def test_human_roles_unchanged_by_this_phase():
    assert rbac.ROLE_PERMISSIONS["admin"] == {"*"}
    assert rbac.ROLE_PERMISSIONS["soc_analyst"] == {"read", "audit", "defense.*", "investigate.*"}
    assert rbac.ROLE_PERMISSIONS["noc_operator"] == {
        "read", "noc.*", "defense.block_ip", "defense.unblock_ip",
        "billing.run_cycle.trigger",
    }
    assert rbac.ROLE_PERMISSIONS["auditor"] == {"read", "audit"}
    assert rbac.ROLE_PERMISSIONS["readonly"] == {"read"}


def test_no_new_service_principal_constant_introduced_by_6r():
    """A Fase 6R REAPROVEITA os Service Principals já existentes
    (SERVICE_HONEYPOT/HONEYTOKEN/PLAYBOOK/RECONCILE, criados na Fase 5A) — não
    introduz nenhuma constante SERVICE_*_PRINCIPAL nova."""
    for principal in _ACTIONS_TO_PRINCIPAL.values():
        assert principal.role == "service"


# ============ Matriz de autorização por PRINCIPAL (evaluate direto) ============
#
# Prova, no nível da policy engine, que cada ação só é autorizada pelo seu
# Service Principal EXATO — e que qualquer outro principal service, papel humano,
# ausência de contexto ou actor forjado como string resultam em DENY.

def _decision(action: str, principal=None, *, actor: str = "", role: str = ""):
    """Avalia `action` sob o Principal de contexto dado (ou nenhum). Retorna o
    Decision. Alvo público não-crítico para separar a decisão de identidade da
    trava de alvo."""
    from contextlib import nullcontext

    from core.policy_engine import evaluate

    ctx = cp.principal_context(principal) if principal is not None else nullcontext()
    with ctx:
        req = cp.make_request(action, target="1.2.3.4", actor=actor, role=role)
        return evaluate(req).decision


_ALL_SERVICE_PRINCIPALS = {
    "honeypot": rbac.SERVICE_HONEYPOT_PRINCIPAL,
    "honeytoken": rbac.SERVICE_HONEYTOKEN_PRINCIPAL,
    "playbook": rbac.SERVICE_PLAYBOOK_PRINCIPAL,
    "reconcile": rbac.SERVICE_RECONCILE_PRINCIPAL,
    "billing": rbac.SERVICE_BILLING_PRINCIPAL,
    "siem": rbac.SERVICE_SIEM_PRINCIPAL,
    "monitor": rbac.SERVICE_MONITOR_PRINCIPAL,
    "watchdog": rbac.SERVICE_WATCHDOG_PRINCIPAL,
}


@pytest.mark.parametrize("action,owner", list(_ACTIONS_TO_PRINCIPAL.items()))
def test_correct_service_principal_is_authorized(action, owner):
    """Principal correto → a decisão NÃO é o DENY de identidade (chega ao resto
    da política; com alvo público e modo real é ALLOW)."""
    from core.models import Decision

    assert _decision(action, owner) is Decision.ALLOW


@pytest.mark.parametrize("action,owner", list(_ACTIONS_TO_PRINCIPAL.items()))
def test_every_other_service_principal_is_denied(action, owner):
    """O RISCO CENTRAL da reauditoria: principals service que compartilham
    role="service" mas NÃO são o dono da ação → DENY. Cobre explicitamente
    service:billing→playbook, service:siem→honeypot, service:monitor→reconcile,
    service:honeypot→honeytoken, service:reconcile→playbook."""
    from core.models import Decision

    for name, principal in _ALL_SERVICE_PRINCIPALS.items():
        if principal.actor == owner.actor:
            continue
        assert _decision(action, principal) is Decision.DENY, (
            f"{principal.actor} NÃO deveria poder {action}")


def test_named_cross_privilege_cases_are_all_denied():
    from core.models import Decision

    cases = [
        ("playbook.auto_isolate", rbac.SERVICE_BILLING_PRINCIPAL),
        ("honeypot.auto_isolate", rbac.SERVICE_SIEM_PRINCIPAL),
        ("reconcile.reapply_block", rbac.SERVICE_MONITOR_PRINCIPAL),
        ("honeytoken.auto_isolate", rbac.SERVICE_HONEYPOT_PRINCIPAL),
        ("playbook.auto_isolate", rbac.SERVICE_RECONCILE_PRINCIPAL),
    ]
    for action, principal in cases:
        assert _decision(action, principal) is Decision.DENY


@pytest.mark.parametrize("action", list(_ACTIONS_TO_PRINCIPAL))
def test_human_roles_denied(action):
    from core.models import Decision

    for principal in (rbac.Principal("user:bob", "readonly"),
                      rbac.Principal("user:soc", "soc_analyst"),
                      rbac.Principal("user:noc", "noc_operator"),
                      rbac.Principal("user:aud", "auditor")):
        assert _decision(action, principal) is Decision.DENY


@pytest.mark.parametrize("action", list(_ACTIONS_TO_PRINCIPAL))
def test_admin_is_not_a_shortcut(action):
    """admin tem "*" no RBAC, mas NÃO é atalho para os fluxos automáticos: sem
    ser o Service Principal dono, é NEGADO."""
    from core.models import Decision

    assert _decision(action, rbac.Principal("local_admin", "admin")) is Decision.DENY


@pytest.mark.parametrize("action", list(_ACTIONS_TO_PRINCIPAL))
def test_no_authenticated_context_is_denied(action):
    """Sem Principal no contexto → fail-closed DENY (mesmo com actor default)."""
    from core.models import Decision

    assert _decision(action) is Decision.DENY


@pytest.mark.parametrize("action,owner", list(_ACTIONS_TO_PRINCIPAL.items()))
def test_forged_actor_string_without_context_is_denied(action, owner):
    """actor forjado apenas como STRING na requisição, sem principal_context
    autenticado → DENY. A autorização amarra ao Principal do contexto, não à
    string livre do ActionRequest — impede falsificação de identidade."""
    from core.models import Decision

    assert _decision(action, None, actor=owner.actor, role="admin") is Decision.DENY


def test_runtime_precheck_also_enforces_allowlist():
    """O overlay runtime_precheck (usado pelo gate de aprovação) aplica a MESMA
    autorização por principal — não é um caminho paralelo sem gate."""
    from contextlib import nullcontext

    from core.models import Decision
    from core.policy_engine import runtime_precheck

    with nullcontext():
        req = cp.make_request("playbook.auto_isolate", target="1.2.3.4",
                              actor="service:playbook", role="admin")
        assert runtime_precheck(req).decision is Decision.DENY  # sem contexto autenticado
    with cp.principal_context(rbac.SERVICE_BILLING_PRINCIPAL):
        req = cp.make_request("playbook.auto_isolate", target="1.2.3.4")
        assert runtime_precheck(req).decision is Decision.DENY  # principal errado
