"""Testes para tools/playbook.py — motor de resposta escalonada.

Toda interação com firewall real é mockada via monkeypatch no objeto do
módulo, não via string-path (evita o erro 'tools.playbook is not a
package' que ocorre quando o módulo tem o mesmo nome de um submódulo
inexistente).
"""

import importlib

import pytest


@pytest.fixture
def pb(monkeypatch, tmp_path):
    """Retorna (playbook_module, dbmod, config) com DB isolado e
    configuração base PLAYBOOK_AUTO_LEVEL=0."""
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", tmp_path / "test_pb.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    monkeypatch.setattr(cfg, "PLAYBOOK_AUTO_LEVEL", 0)
    import tools.playbook as playbook
    importlib.reload(playbook)

    yield playbook, dbmod, cfg


# ---------- list_playbooks ----------

def test_list_playbooks_contains_all_attack_types(pb):
    playbook, _, _ = pb
    result = playbook.list_playbooks()
    for t in ["port_scan", "brute_force", "honeypot_trap", "honeynet_violation",
              "ddos_volumetric", "honeytoken_trigger", "web_attack", "recon_confirmed"]:
        assert t in result


def test_list_playbooks_shows_auto_level_zero(pb):
    playbook, _, _ = pb
    result = playbook.list_playbooks()
    assert "PLAYBOOK_AUTO_LEVEL=0" in result or "só avalia" in result


# ---------- _determine_level ----------

def test_port_scan_base_level_1(pb):
    playbook, _, _ = pb
    assert playbook._determine_level("port_scan", score=0) == 1


def test_brute_force_base_level_2(pb):
    playbook, _, _ = pb
    assert playbook._determine_level("brute_force", score=0) == 2


def test_reoffender_bumps_port_scan_to_level_2(pb):
    playbook, _, _ = pb
    assert playbook._determine_level("port_scan", score=10) == 2


def test_reoffender_bumps_ddos_to_level_3(pb):
    playbook, _, _ = pb
    assert playbook._determine_level("ddos_volumetric", score=10) == 3


def test_brute_force_no_bump_even_with_high_score(pb):
    """brute_force.reoffender_bump=False — score alto não sobe o nível."""
    playbook, _, _ = pb
    assert playbook._determine_level("brute_force", score=100) == 2


def test_unknown_attack_type_defaults_level_1(pb):
    playbook, _, _ = pb
    assert playbook._determine_level("totally_unknown_attack", score=0) == 1


# ---------- evaluate_and_respond — nível automático 0 ----------

def test_auto_level_0_no_firewall_calls(pb, monkeypatch):
    playbook, _, _ = pb
    blocked, throttled = [], []
    monkeypatch.setattr(playbook.firewall, "rate_limit_ip",
                        lambda ip, **kw: throttled.append(ip) or "ok")
    monkeypatch.setattr(playbook.firewall, "block_ip",
                        lambda ip, **kw: blocked.append(ip) or "ok")

    playbook.evaluate_and_respond("1.2.3.4", "port_scan")
    assert throttled == []
    assert blocked == []


def test_auto_level_0_result_describes_suggestion(pb, monkeypatch):
    playbook, _, _ = pb
    monkeypatch.setattr(playbook.firewall, "rate_limit_ip", lambda *a, **kw: "ok")
    result = playbook.evaluate_and_respond("1.2.3.4", "port_scan")
    assert "PLAYBOOK_AUTO_LEVEL=0" in result or "sugeridas" in result or "Nenhuma ação" in result


# ---------- evaluate_and_respond — nível automático 1 ----------

def test_auto_level_1_throttles_not_blocks(pb, monkeypatch):
    playbook, _, cfg = pb
    monkeypatch.setattr(playbook, "PLAYBOOK_AUTO_LEVEL", 1)

    throttled, blocked = [], []
    monkeypatch.setattr(playbook.firewall, "rate_limit_ip",
                        lambda ip, **kw: throttled.append(ip) or "throttled")
    monkeypatch.setattr(playbook.firewall, "block_ip",
                        lambda ip, **kw: blocked.append(ip) or "blocked")
    monkeypatch.setattr(playbook, "record_confirmed_isolation", lambda *a, **kw: None)

    playbook.evaluate_and_respond("1.2.3.4", "port_scan")
    assert throttled == ["1.2.3.4"]
    assert blocked == []


# ---------- evaluate_and_respond — nível automático 2 ----------

def test_auto_level_2_throttles_and_blocks(pb, monkeypatch):
    playbook, _, _ = pb
    monkeypatch.setattr(playbook, "PLAYBOOK_AUTO_LEVEL", 2)

    throttled, blocked = [], []
    monkeypatch.setattr(playbook.firewall, "rate_limit_ip",
                        lambda ip, **kw: throttled.append(ip) or "throttled")
    monkeypatch.setattr(playbook.firewall, "block_ip",
                        lambda ip, **kw: blocked.append(ip) or "blocked")
    monkeypatch.setattr(playbook, "record_confirmed_isolation", lambda *a, **kw: None)

    # CP-SD Fase 6R (endurecimento): o isolamento de nível 2 só executa sob a
    # identidade de serviço autenticada — instalamos service:playbook aqui para
    # exercitar a LÓGICA de nível 2 (throttle + block) sob autorização. Na
    # chamada humana real (sem esse contexto) o bloqueio é NEGADO — coberto em
    # test_defense_subsystems_control_plane.py::
    # test_playbook_human_call_throttles_but_isolation_denied.
    from core import control_plane as cp
    from core import rbac
    with cp.principal_context(rbac.SERVICE_PLAYBOOK_PRINCIPAL):
        playbook.evaluate_and_respond("1.2.3.4", "honeypot_trap")
    assert throttled == ["1.2.3.4"]
    assert blocked == ["1.2.3.4"]


# ---------- BARREIRA CRÍTICA: nível 3 nunca automático ----------

def test_level3_never_auto_regardless_of_config(pb, monkeypatch):
    """BARREIRA NÃO NEGOCIÁVEL: nível 3 (BGP FlowSpec) nunca executa
    automaticamente, mesmo com PLAYBOOK_AUTO_LEVEL=99. O _AUTO_CAP=2
    limita programaticamente o nível máximo auto-executável."""
    import tools.bgp_flowspec as bgp

    playbook, _, _ = pb
    monkeypatch.setattr(playbook, "PLAYBOOK_AUTO_LEVEL", 99)

    bgp_called = []
    monkeypatch.setattr(bgp, "announce_flowspec_rule",
                        lambda *a, **kw: bgp_called.append(a) or "SHOULD_NOT_RUN")
    monkeypatch.setattr(playbook.firewall, "rate_limit_ip", lambda *a, **kw: "ok")
    monkeypatch.setattr(playbook.firewall, "block_ip", lambda *a, **kw: "ok")
    monkeypatch.setattr(playbook, "record_confirmed_isolation", lambda *a, **kw: None)

    result = playbook.evaluate_and_respond("1.2.3.4", "ddos_volumetric")
    assert bgp_called == [], "BGP FlowSpec foi chamado automaticamente — BARREIRA VIOLADA"
    assert "SHOULD_NOT_RUN" not in result


# ---------- integração com DB ----------

def test_evaluate_records_execution_in_db(pb, monkeypatch):
    playbook, dbmod, _ = pb
    monkeypatch.setattr(playbook.firewall, "rate_limit_ip", lambda *a, **kw: "ok")
    monkeypatch.setattr(playbook.firewall, "block_ip", lambda *a, **kw: "ok")

    playbook.evaluate_and_respond("5.5.5.5", "port_scan")

    rows = dbmod.list_playbook_executions("5.5.5.5")
    assert len(rows) == 1
    assert rows[0][0] == "5.5.5.5"
    assert rows[0][1] == "port_scan"


def test_repeat_offender_bumps_level_via_db(pb):
    """Score gravado no DB deve influenciar o nível determinado."""
    playbook, dbmod, _ = pb
    for _ in range(5):
        dbmod.record_threat_isolation("2.2.2.2")

    score = playbook._get_score("2.2.2.2")
    assert score >= 10
    level = playbook._determine_level("port_scan", score)
    assert level == 2


# ---------- describe_playbook_history ----------

def test_describe_history_empty(pb):
    playbook, _, _ = pb
    assert "Nenhum playbook" in playbook.describe_playbook_history()


def test_describe_history_shows_records(pb, monkeypatch):
    playbook, _, _ = pb
    monkeypatch.setattr(playbook.firewall, "rate_limit_ip", lambda *a, **kw: "ok")
    monkeypatch.setattr(playbook.firewall, "block_ip", lambda *a, **kw: "ok")

    playbook.evaluate_and_respond("9.9.9.9", "brute_force")
    result = playbook.describe_playbook_history()
    assert "9.9.9.9" in result
    assert "brute_force" in result


def test_describe_history_filters_by_ip(pb, monkeypatch):
    playbook, _, _ = pb
    monkeypatch.setattr(playbook.firewall, "rate_limit_ip", lambda *a, **kw: "ok")
    monkeypatch.setattr(playbook.firewall, "block_ip", lambda *a, **kw: "ok")

    playbook.evaluate_and_respond("10.0.0.1", "port_scan")
    playbook.evaluate_and_respond("10.0.0.2", "web_attack")

    result = playbook.describe_playbook_history("10.0.0.1")
    assert "10.0.0.1" in result
    assert "10.0.0.2" not in result
