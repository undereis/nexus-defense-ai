"""CP-SD Fase 6O — as duas chamadas diretas de firewall.block_ip dentro de
main.py:monitor_loop (bloqueio proativo por threat feed + auto-isolamento
por DDoS/volume severo) passam pelo Control Plane antes de qualquer
mutação real de firewall.

Achado da Fase 6N (scoping): nenhuma das duas chamadas tinha RBAC,
identidade ou trava de infraestrutura crítica — só o cinto de modo (lab/
replay) de tools/firewall.py protegia, e só contra execução no modo
errado, não contra alvo errado. Novo action_type "monitor.auto_isolate"
(changes_state=True, MEDIUM, sem aprovação) cobre os DOIS caminhos,
diferenciados por params["source"] ("threat_feed"/"ddos_severe") — a
decisão de governança é a mesma, só o motivo de detecção difere.

O teste mais importante desta fase é o de IP de infraestrutura crítica
(#5/#6 abaixo): antes desta fase, NADA impedia o monitor_loop de
auto-bloquear um IP próprio crítico (DNS, roteador) se ele aparecesse
(por engano ou feed envenenado) como ameaça — a Fase 6O fecha esse buraco
via asset_registry.check_target, reaproveitado automaticamente pela
policy engine.

Nenhum firewall/rede/subprocess real: firewall.block_ip é sempre
mockado; o backstop autouse de tests/security/conftest.py bloqueia
subprocess.run/requests.post/get reais como defesa adicional. DB sempre
temporário (fixture autouse clean_db). monitor_loop roda por EXATAMENTE
1 iteração (stop_event.wait mockado para setar o evento na 1ª chamada),
mesmo padrão de tests/security/test_monitor_loop_service_principal.py.
"""

import threading

import pytest

import database.db as db_module
import main as main_module
from core import control_plane as cp
from core import rbac
from tools import infrastructure


@pytest.fixture(autouse=True)
def _reset_monitor_auto_isolate_cooldown(monkeypatch):
    """CP-SD Fase 6Q: `_monitor_auto_isolate_cooldown` é um dict real do
    módulo (não recriado por `_run_one_iteration`, de propósito — os testes
    de cooldown precisam que ele SOBREVIVA entre múltiplas chamadas dentro
    do MESMO teste). Sem este fixture, o estado vazaria entre testes
    diferentes na mesma sessão do pytest."""
    monkeypatch.setattr(main_module, "_monitor_auto_isolate_cooldown", {})


def _install_fake_monotonic(monkeypatch, start: float = 1_000_000.0) -> dict:
    """Substitui time.monotonic() por um relógio controlável em memória —
    nenhum teste de cooldown depende de tempo real/sleep."""
    state = {"now": start}
    monkeypatch.setattr(main_module.time, "monotonic", lambda: state["now"])
    return state


def _decision_count() -> int:
    return len(_cp_decision_events())


def _cp_decision_events() -> list[str]:
    """Linhas de auditoria que só existem se o Control Plane foi
    efetivamente consultado."""
    with db_module.get_conn() as conn:
        rows = conn.execute(
            "SELECT detail FROM events WHERE event_type IN "
            "('control_plane_decision', 'control_plane_executed')"
        ).fetchall()
    return [r[0] for r in rows]


def _cp_decision_targets() -> list[str]:
    """source_ip (= req.target) das linhas de auditoria do Control Plane."""
    with db_module.get_conn() as conn:
        rows = conn.execute(
            "SELECT source_ip FROM events WHERE event_type IN "
            "('control_plane_decision', 'control_plane_executed')"
        ).fetchall()
    return [r[0] for r in rows]


def _run_one_iteration(
    monkeypatch, *, severe_ips=(), moderate_ips=(), feed_ips=None,
    fake_block_result="bloqueado (fake)",
):
    """Roda monitor_loop por EXATAMENTE uma iteração. `feed_ips`: dict
    ip -> lista de fontes de match em check_ip_against_feeds (default {} =
    nenhum IP em nenhum feed)."""
    feed_ips = feed_ips or {}
    all_ips = list(severe_ips) + list(moderate_ips) + list(feed_ips)
    fake_counts = {ip: 999 for ip in all_ips}

    block_calls: list[tuple] = []
    confirmed_calls: list[tuple] = []
    announce_calls: list[str] = []
    notify_calls: list[tuple] = []
    ask_agent_calls: list[dict] = []

    monkeypatch.setattr(main_module._detector, "sample", lambda: [])
    monkeypatch.setattr(main_module._detector, "snapshot_counts", lambda: fake_counts)
    monkeypatch.setattr(main_module, "_last_alerted", {})
    monkeypatch.setattr(main_module, "_feed_blocked_ips", set())
    monkeypatch.setattr(main_module, "record_current_sample", lambda *a, **k: None)
    monkeypatch.setattr(main_module, "record_all_client_samples", lambda *a, **k: None)
    monkeypatch.setattr(main_module, "check_all_client_anomalies", lambda *a, **k: [])
    monkeypatch.setattr(main_module, "check_ip_against_feeds", lambda ip: feed_ips.get(ip, []))
    monkeypatch.setattr(
        main_module, "classify_threats",
        lambda *a, **k: (list(severe_ips), list(moderate_ips)),
    )
    monkeypatch.setattr(main_module, "correlate_and_escalate", lambda ip: None)
    monkeypatch.setattr(main_module, "is_repeat_offender", lambda ip: False)
    monkeypatch.setattr(main_module, "_due_for_alert", lambda ips, now: list(ips))
    monkeypatch.setattr(main_module, "get_findings_for_host", lambda ip, limit=3: [])

    def fake_block(ip, reason):
        block_calls.append((ip, reason))
        return fake_block_result

    monkeypatch.setattr(main_module.firewall, "block_ip", fake_block)

    def fake_confirmed(ip, reason):
        confirmed_calls.append((ip, reason))

    monkeypatch.setattr(main_module, "record_confirmed_isolation", fake_confirmed)

    def fake_notify(subject, body):
        notify_calls.append((subject, body))

    monkeypatch.setattr(main_module, "send_notification", fake_notify)
    monkeypatch.setattr(main_module, "log_event", lambda *a, **k: None)

    def fake_announce(msg):
        announce_calls.append(msg)

    monkeypatch.setattr(main_module, "_announce", fake_announce)

    def fake_ask_agent(text, principal=None):
        ask_agent_calls.append({"text": text, "principal": principal})
        return "ok (fake)"

    monkeypatch.setattr(main_module, "ask_agent", fake_ask_agent)

    stop_event = threading.Event()
    monkeypatch.setattr(stop_event, "wait", lambda timeout=None: stop_event.set())

    main_module.monitor_loop(stop_event)

    return {
        "block_calls": block_calls,
        "confirmed_calls": confirmed_calls,
        "announce_calls": announce_calls,
        "notify_calls": notify_calls,
        "ask_agent_calls": ask_agent_calls,
        "feed_blocked_ips": set(main_module._feed_blocked_ips),
    }


# ===================== Caminho threat feed =====================

def test_threat_feed_allow_executes_and_preserves_behavior(monkeypatch):
    ip = "203.0.113.50"
    assert cp.get_current_principal() is None

    reason = "IP em feed(s) de threat intel conhecido: spamhaus_drop"
    result = _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop"]})

    assert result["block_calls"] == [(ip, reason)]
    assert result["confirmed_calls"] == [(ip, reason)]
    assert ip in result["feed_blocked_ips"]
    assert any("BLOQUEIO PROATIVO (threat feed)" in m for m in result["announce_calls"])
    assert any(ip in body for _subj, body in result["notify_calls"])


def test_threat_feed_allow_uses_service_monitor_principal_when_no_context(monkeypatch):
    """Confirma que o disparo em si (não só o ask_agent de narração) usa a
    identidade correta via auditoria do Control Plane."""
    ip = "203.0.113.51"

    _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop"]})

    blob = " ".join(_cp_decision_events())
    assert "action=monitor.auto_isolate" in blob
    assert "actor=service:monitor" in blob
    assert "role=service" in blob
    assert ip in _cp_decision_targets()


def test_threat_feed_deny_never_blocks(monkeypatch):
    ip = "203.0.113.52"
    readonly = rbac.Principal("user:bob", "readonly")

    def _run():
        with cp.principal_context(readonly):
            return _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop"]})

    result = _run()

    assert result["block_calls"] == []
    assert result["confirmed_calls"] == []
    assert ip not in result["feed_blocked_ips"]
    assert not any("BLOQUEIO PROATIVO" in m for m in result["announce_calls"])
    assert result["notify_calls"] == []


def test_threat_feed_dry_run_lab_never_blocks(monkeypatch):
    from core import operating_mode

    ip = "203.0.113.53"
    operating_mode.set_operating_mode("lab")

    result = _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop"]})

    assert result["block_calls"] == []
    assert result["confirmed_calls"] == []
    assert ip not in result["feed_blocked_ips"]
    assert not any("BLOQUEIO PROATIVO" in m for m in result["announce_calls"])


def test_threat_feed_dry_run_replay_never_blocks(monkeypatch):
    from core import operating_mode

    ip = "203.0.113.54"
    operating_mode.set_operating_mode("replay")

    result = _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop"]})

    assert result["block_calls"] == []
    assert result["confirmed_calls"] == []
    assert ip not in result["feed_blocked_ips"]


# ===================== IP de infraestrutura crítica (teste mais importante) =====================

def test_threat_feed_critical_infra_ip_is_never_blocked(monkeypatch):
    """Antes da Fase 6O, NADA impedia isto: um IP próprio crítico (DNS,
    roteador) marcado errado por um feed envenenado/comprometido seria
    auto-bloqueado sem qualquer checagem. A trava vem de
    asset_registry.check_target, reaproveitada automaticamente pela policy
    engine — não precisou de nenhum código novo em main.py para isso."""
    critical_ip = "203.0.113.55"
    monkeypatch.setattr(infrastructure, "is_critical_ip", lambda ip: ip == critical_ip)

    result = _run_one_iteration(monkeypatch, feed_ips={critical_ip: ["spamhaus_drop"]})

    assert result["block_calls"] == []
    assert result["confirmed_calls"] == []
    assert critical_ip not in result["feed_blocked_ips"]


def test_ddos_severe_critical_infra_ip_is_never_blocked(monkeypatch):
    """Mesma trava, caminho DDoS/severo — prova que a proteção não é
    específica do caminho threat feed, e sim do helper compartilhado
    _monitor_auto_isolate."""
    critical_ip = "203.0.113.56"
    monkeypatch.setattr(infrastructure, "is_critical_ip", lambda ip: ip == critical_ip)

    result = _run_one_iteration(monkeypatch, severe_ips=[critical_ip])

    assert result["block_calls"] == []
    assert result["confirmed_calls"] == []
    assert result["ask_agent_calls"] == []


# ===================== Caminho DDoS/severe =====================

def test_ddos_severe_allow_executes_and_preserves_behavior(monkeypatch):
    ip = "203.0.113.60"

    result = _run_one_iteration(monkeypatch, severe_ips=[ip])

    assert len(result["block_calls"]) == 1
    assert result["block_calls"][0][0] == ip
    assert len(result["confirmed_calls"]) == 1
    assert any("AÇÃO AUTOMÁTICA" in m for m in result["announce_calls"])
    assert any(ip in body for _subj, body in result["notify_calls"])
    assert len(result["ask_agent_calls"]) == 1
    assert result["ask_agent_calls"][0]["principal"] == rbac.SERVICE_MONITOR_PRINCIPAL
    assert "AVISO: acabei de isolar automaticamente" in result["ask_agent_calls"][0]["text"]


def test_ddos_severe_deny_never_blocks_and_does_not_narrate(monkeypatch):
    ip = "203.0.113.61"
    readonly = rbac.Principal("user:bob", "readonly")

    with cp.principal_context(readonly):
        result = _run_one_iteration(monkeypatch, severe_ips=[ip])

    assert result["block_calls"] == []
    assert result["confirmed_calls"] == []
    assert not any("AÇÃO AUTOMÁTICA" in m for m in result["announce_calls"])
    assert result["notify_calls"] == []
    # não mascara DENY como "acabei de isolar" para o agente
    assert result["ask_agent_calls"] == []


def test_ddos_severe_dry_run_lab_never_blocks(monkeypatch):
    from core import operating_mode

    ip = "203.0.113.62"
    operating_mode.set_operating_mode("lab")

    result = _run_one_iteration(monkeypatch, severe_ips=[ip])

    assert result["block_calls"] == []
    assert result["confirmed_calls"] == []
    assert result["ask_agent_calls"] == []


def test_ddos_severe_dry_run_replay_never_blocks(monkeypatch):
    from core import operating_mode

    ip = "203.0.113.63"
    operating_mode.set_operating_mode("replay")

    result = _run_one_iteration(monkeypatch, severe_ips=[ip])

    assert result["block_calls"] == []
    assert result["confirmed_calls"] == []


# ===================== RBAC / ActionSpec / Service Principal =====================

def test_service_role_gained_monitor_auto_isolate_permission():
    perms = rbac.ROLE_PERMISSIONS["service"]
    assert "monitor.auto_isolate" in perms


def test_service_role_did_not_gain_defense_block_ip_or_wildcards():
    perms = rbac.ROLE_PERMISSIONS["service"]
    assert "defense.block_ip" not in perms
    assert "defense.*" not in perms
    assert "monitor.*" not in perms
    assert "*" not in perms
    assert "admin" not in perms


def test_human_roles_unchanged_by_this_phase():
    assert rbac.ROLE_PERMISSIONS["admin"] == {"*"}
    assert rbac.ROLE_PERMISSIONS["soc_analyst"] == {"read", "audit", "defense.*", "investigate.*"}
    assert rbac.ROLE_PERMISSIONS["noc_operator"] == {
        "read", "noc.*", "defense.block_ip", "defense.unblock_ip",
        "billing.run_cycle.trigger",
    }
    assert rbac.ROLE_PERMISSIONS["auditor"] == {"read", "audit"}
    assert rbac.ROLE_PERMISSIONS["readonly"] == {"read"}


def test_service_role_full_permission_set_after_phase_6o():
    """Conjunto EXATO e atual de 'service' — autoritativo a partir da Fase
    6O. Testes de fases anteriores que afirmavam um conjunto exato foram
    convertidos para subconjunto (mesmo padrão repetido em toda fase que
    acrescenta permissão a 'service')."""
    assert rbac.ROLE_PERMISSIONS["service"] == {
        "read",
        "risk.sweep_expired", "audit.checkpoint", "watchdog.check_health", "report.generate",
        "noc.block_subscriber", "noc.unblock_subscriber",
        "billing.run_cycle.trigger",
        "siem.forward_events",
        "threat_feed.refresh_lists",
        "monitor.auto_isolate",
    }


def test_action_spec_monitor_auto_isolate():
    from core.policy_engine import ACTION_CATALOG

    spec = ACTION_CATALOG["monitor.auto_isolate"]
    assert spec.required_permission == "monitor.auto_isolate"
    assert spec.changes_state is True
    assert spec.risk is cp.ActionRisk.MEDIUM
    assert spec.requires_approval is False


def test_service_monitor_principal_exists_and_is_not_admin():
    assert rbac.SERVICE_MONITOR_PRINCIPAL.role == "service"
    assert rbac.SERVICE_MONITOR_PRINCIPAL.role != "admin"
    assert rbac.SERVICE_MONITOR_PRINCIPAL.actor == "service:monitor"


# ===================== Sem ameaças: comportamento antigo preservado =====================

def test_monitor_loop_without_threats_does_not_call_cp_or_agent(monkeypatch):
    result = _run_one_iteration(monkeypatch)
    assert result["block_calls"] == []
    assert result["ask_agent_calls"] == []


# =====================================================================
# CP-SD Fase 6Q — cooldown em memória para monitor.auto_isolate em
# DENY/DRY_RUN_ONLY
#
# Achado da Fase 6P: o caminho threat_feed podia reauditar o MESMO IP a
# cada MONITOR_POLL_INTERVAL (5s) indefinidamente em DENY/DRY_RUN_ONLY,
# porque `_feed_blocked_ips` só é atualizado em EXECUTED (decisão da
# Fase 6O, correta — não reverter). O caminho ddos_severe já tinha um
# amortecedor pré-existente e independente (`_last_alerted`/
# `ALERT_COOLDOWN_SECONDS=300s`, aqui neutralizado de propósito via
# `_due_for_alert` mockado para `list(ips)`, para isolar e testar
# especificamente o cooldown NOVO desta fase). Chave (ip, source) —
# NUNCA ip sozinho. TTL = ALERT_COOLDOWN_SECONDS (300s), não os 1800s da
# SIEM (Fase 6K) — monitor_loop é detecção em tempo real.
# =====================================================================

def test_threat_feed_deny_first_attempt_is_audited(monkeypatch):
    ip = "203.0.113.70"
    readonly = rbac.Principal("user:bob", "readonly")
    _install_fake_monotonic(monkeypatch)

    with cp.principal_context(readonly):
        before = _decision_count()
        result = _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop"]})

    assert result["block_calls"] == []
    assert _decision_count() > before


def test_threat_feed_deny_repeated_within_cooldown_is_suppressed(monkeypatch):
    ip = "203.0.113.71"
    readonly = rbac.Principal("user:bob", "readonly")
    _install_fake_monotonic(monkeypatch)

    with cp.principal_context(readonly):
        _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop"]})
        after_first = _decision_count()
        result2 = _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop"]})

    assert _decision_count() == after_first  # nenhum control_plane_decision novo
    assert result2["block_calls"] == []
    assert result2["confirmed_calls"] == []
    assert ip not in result2["feed_blocked_ips"]
    assert result2["announce_calls"] == []
    assert result2["notify_calls"] == []


def test_threat_feed_dry_run_lab_repeated_within_cooldown_is_suppressed(monkeypatch):
    from core import operating_mode

    ip = "203.0.113.72"
    operating_mode.set_operating_mode("lab")
    _install_fake_monotonic(monkeypatch)

    _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop"]})
    after_first = _decision_count()
    result2 = _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop"]})

    assert _decision_count() == after_first
    assert result2["block_calls"] == []


def test_threat_feed_dry_run_replay_repeated_within_cooldown_is_suppressed(monkeypatch):
    from core import operating_mode

    ip = "203.0.113.73"
    operating_mode.set_operating_mode("replay")
    _install_fake_monotonic(monkeypatch)

    _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop"]})
    after_first = _decision_count()
    result2 = _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop"]})

    assert _decision_count() == after_first
    assert result2["block_calls"] == []


def test_threat_feed_reaudits_after_ttl_expires(monkeypatch):
    ip = "203.0.113.74"
    readonly = rbac.Principal("user:bob", "readonly")
    clock = _install_fake_monotonic(monkeypatch)

    with cp.principal_context(readonly):
        _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop"]})
        after_first = _decision_count()

        clock["now"] += main_module.MONITOR_AUTO_ISOLATE_COOLDOWN_SECONDS + 1

        _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop"]})

    assert _decision_count() > after_first


def test_threat_feed_reaudits_immediately_if_mode_changed(monkeypatch):
    from core import operating_mode

    ip = "203.0.113.75"
    operating_mode.set_operating_mode("lab")
    _install_fake_monotonic(monkeypatch)

    _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop"]})
    after_first = _decision_count()

    operating_mode.set_operating_mode("real")
    result2 = _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop"]})

    assert _decision_count() > after_first
    # sem Principal explícito -> service:monitor, que TEM a permissão; modo
    # real -> ALLOW de verdade agora que o cooldown antigo (do modo lab) foi
    # invalidado pela mudança de modo.
    assert len(result2["block_calls"]) == 1
    assert (ip, "threat_feed") not in main_module._monitor_auto_isolate_cooldown


def test_threat_feed_reaudits_immediately_if_feeds_changed(monkeypatch):
    ip = "203.0.113.76"
    readonly = rbac.Principal("user:bob", "readonly")
    _install_fake_monotonic(monkeypatch)

    with cp.principal_context(readonly):
        _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop"]})
        after_first = _decision_count()

        _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop", "feodo_tracker"]})

    assert _decision_count() > after_first


def test_executed_clears_cooldown(monkeypatch):
    ip = "203.0.113.77"
    from core import operating_mode

    operating_mode.set_operating_mode("lab")
    _install_fake_monotonic(monkeypatch)

    _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop"]})
    assert (ip, "threat_feed") in main_module._monitor_auto_isolate_cooldown

    operating_mode.set_operating_mode("real")
    result2 = _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop"]})

    assert len(result2["block_calls"]) == 1
    assert ip in result2["feed_blocked_ips"]
    assert (ip, "threat_feed") not in main_module._monitor_auto_isolate_cooldown


def test_ddos_severe_deny_repeated_within_cooldown_is_suppressed(monkeypatch):
    """`_due_for_alert` continua mockado para `list(ips)` (neutraliza o
    amortecedor pré-existente de ALERT_COOLDOWN_SECONDS/_last_alerted) —
    isola e prova o cooldown NOVO desta fase, independente do mecanismo
    antigo, que continua intacto para o uso real do produto."""
    ip = "203.0.113.78"
    readonly = rbac.Principal("user:bob", "readonly")
    _install_fake_monotonic(monkeypatch)

    with cp.principal_context(readonly):
        _run_one_iteration(monkeypatch, severe_ips=[ip])
        after_first = _decision_count()
        result2 = _run_one_iteration(monkeypatch, severe_ips=[ip])

    assert _decision_count() == after_first
    assert result2["block_calls"] == []
    assert result2["confirmed_calls"] == []
    assert result2["ask_agent_calls"] == []


def test_cooldown_key_is_per_ip_and_source_not_shared(monkeypatch):
    """O mesmo IP em threat_feed E ddos_severe simultaneamente gera 2
    entradas de cooldown INDEPENDENTES — suprimir uma não deve suprimir a
    outra por engano."""
    ip = "203.0.113.79"
    readonly = rbac.Principal("user:bob", "readonly")
    _install_fake_monotonic(monkeypatch)

    with cp.principal_context(readonly):
        _run_one_iteration(monkeypatch, feed_ips={ip: ["spamhaus_drop"]}, severe_ips=[ip])
        assert (ip, "threat_feed") in main_module._monitor_auto_isolate_cooldown
        assert (ip, "ddos_severe") in main_module._monitor_auto_isolate_cooldown
        after_first = _decision_count()

        result2 = _run_one_iteration(
            monkeypatch, feed_ips={ip: ["spamhaus_drop"]}, severe_ips=[ip],
        )

    # as DUAS tentativas (threat_feed e ddos_severe) foram suprimidas
    # independentemente, cada uma pela SUA PRÓPRIA entrada de cooldown.
    assert _decision_count() == after_first
    assert result2["block_calls"] == []
