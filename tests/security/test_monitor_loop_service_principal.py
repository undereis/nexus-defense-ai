"""CP-SD Fase 5D — monitor_loop (main.py) migrado para Service Principal explícito.

Antes: as DUAS chamadas ask_agent dentro de monitor_loop (narrativa do
isolamento automático severo + avaliação de ameaça moderada pelo agente) não
passavam `principal=`, caindo no fallback local_admin/admin do ask_agent
(Fase 2). Agora ambas passam `principal=rbac.SERVICE_MONITOR_PRINCIPAL`
(Fase 5A) — mudança de 2 linhas, sem alterar periodicidade, textos dos
prompts, lógica de detecção/isolamento/notificação ou try/except. Mesmo
padrão das Fases 5B (reconcile_loop) e 5C (proactive_audit_loop).

Com esta fase, main.py fica com exatamente 4 usos automáticos de
`principal=`: 2 no monitor_loop, 1 no proactive_audit_loop (5C), 1 no
reconcile_loop (5B). O loop interativo do CLI continua chamando ask_agent
sem principal de propósito (Fase 2: só o CLI local pode).

Nenhum loop real roda: monitor_loop é chamado uma vez com um stop_event cujo
`.wait()` já seta o evento (uma iteração só, sem while infinito real). TODAS
as dependências de detecção/isolamento/notificação são mockadas: _detector
(sample/snapshot_counts), amostragem por cliente, threat feed lists,
classify_threats, correlação de IOC, reincidência, firewall.block_ip,
threat_intel, notify, log_event, _announce e _due_for_alert — nenhum
firewall/rede/AbuseIPDB/Mikrotik/subprocess real, nenhum agente real, nenhum
banco real tocado.
"""

import inspect
import threading

import main as main_module
from core import rbac


def _run_one_iteration(monkeypatch, *, severe_ips, moderate_ips):
    """Roda monitor_loop por EXATAMENTE uma iteração: stop_event.wait() já
    seta o evento na primeira chamada, então o `while not stop_event.is_set()`
    do topo do laço encerra no início da segunda volta — sem while infinito
    real, sem sleep real. Todas as dependências reais (detecção via
    psutil/netstat, firewall, threat_intel, notificação) são substituídas
    por fakes."""
    captured_calls: list[dict] = []
    all_ips = list(severe_ips) + list(moderate_ips)
    fake_counts = {ip: 999 for ip in all_ips}

    # nunca inspeciona conexões reais do SO (psutil/netstat)
    monkeypatch.setattr(main_module._detector, "sample", lambda: [])
    monkeypatch.setattr(main_module._detector, "snapshot_counts", lambda: fake_counts)
    monkeypatch.setattr(main_module, "_last_alerted", {})  # isolamento entre testes
    monkeypatch.setattr(main_module, "record_current_sample", lambda *a, **k: None)
    monkeypatch.setattr(main_module, "record_all_client_samples", lambda *a, **k: None)
    monkeypatch.setattr(main_module, "check_all_client_anomalies", lambda *a, **k: [])
    monkeypatch.setattr(main_module, "check_ip_against_feeds", lambda ip: [])
    monkeypatch.setattr(
        main_module, "classify_threats",
        lambda *a, **k: (list(severe_ips), list(moderate_ips)),
    )
    monkeypatch.setattr(main_module, "correlate_and_escalate", lambda ip: None)
    monkeypatch.setattr(main_module, "is_repeat_offender", lambda ip: False)
    monkeypatch.setattr(main_module, "_due_for_alert", lambda ips, now: list(ips))
    monkeypatch.setattr(main_module, "get_findings_for_host", lambda ip, limit=3: [])
    monkeypatch.setattr(main_module.firewall, "block_ip", lambda ip, reason: "bloqueado (fake)")
    monkeypatch.setattr(main_module, "record_confirmed_isolation", lambda *a, **k: None)
    monkeypatch.setattr(main_module, "send_notification", lambda *a, **k: None)
    monkeypatch.setattr(main_module, "log_event", lambda *a, **k: None)
    monkeypatch.setattr(main_module, "_announce", lambda *a, **k: None)

    def _fake_ask_agent(text, principal=None):
        captured_calls.append({"text": text, "principal": principal})
        return "ok (fake)"

    monkeypatch.setattr(main_module, "ask_agent", _fake_ask_agent)

    stop_event = threading.Event()
    monkeypatch.setattr(stop_event, "wait", lambda timeout=None: stop_event.set())

    main_module.monitor_loop(stop_event)
    return captured_calls


# ------------------------- 1/2: ambos os call-sites usam SERVICE_MONITOR_PRINCIPAL -------------------------

def test_monitor_loop_severe_isolation_call_uses_service_monitor_principal(monkeypatch):
    calls = _run_one_iteration(monkeypatch, severe_ips=["203.0.113.10"], moderate_ips=[])
    assert len(calls) == 1
    assert calls[0]["principal"] == rbac.SERVICE_MONITOR_PRINCIPAL
    assert "203.0.113.10" in calls[0]["text"]
    assert "AVISO: acabei de isolar automaticamente" in calls[0]["text"]


def test_monitor_loop_moderate_evaluation_call_uses_service_monitor_principal(monkeypatch):
    calls = _run_one_iteration(monkeypatch, severe_ips=[], moderate_ips=["203.0.113.20"])
    assert len(calls) == 1
    assert calls[0]["principal"] == rbac.SERVICE_MONITOR_PRINCIPAL
    assert "203.0.113.20" in calls[0]["text"]
    assert "ALERTA AUTOMÁTICO DO MONITOR DE REDE" in calls[0]["text"]


def test_monitor_loop_both_call_sites_in_same_iteration_use_service_monitor_principal(monkeypatch):
    calls = _run_one_iteration(
        monkeypatch, severe_ips=["203.0.113.30"], moderate_ips=["203.0.113.40"]
    )
    assert len(calls) == 2
    assert all(c["principal"] == rbac.SERVICE_MONITOR_PRINCIPAL for c in calls)


def test_monitor_loop_without_threats_does_not_call_ask_agent(monkeypatch):
    """Sem IP severo/moderado, nenhum ramo de ask_agent roda — comportamento
    antigo preservado."""
    calls = _run_one_iteration(monkeypatch, severe_ips=[], moderate_ips=[])
    assert calls == []


# ------------------------- 18: texto dos prompts inalterado -------------------------

def test_monitor_loop_prompt_texts_unchanged():
    src = inspect.getsource(main_module.monitor_loop)
    assert "AVISO: acabei de isolar automaticamente o IP {ip} ({reason}), " in src
    assert "pois estava muito acima do limite configurado." in src
    assert "Confirme que está registrado e me explique resumidamente o que foi feito." in src
    assert (
        "ALERTA AUTOMÁTICO DO MONITOR DE REDE: os seguintes IPs excederam o " in src
    )
    assert "limite de conexões na janela de monitoramento e são suspeitos de DDoS: " in src
    assert "Avalie e decida se deve isolá-los, explicando o motivo." in src


# ------------------------- 11/12: reconcile_loop e proactive_audit_loop mantêm seus Principals -------------------------

def test_reconcile_loop_still_uses_service_reconcile_principal():
    src = inspect.getsource(main_module.reconcile_loop)
    assert src.count("principal=rbac.SERVICE_RECONCILE_PRINCIPAL") == 1


def test_proactive_audit_loop_still_uses_service_proactive_audit_principal():
    src = inspect.getsource(main_module.proactive_audit_loop)
    assert src.count("principal=rbac.SERVICE_PROACTIVE_AUDIT_PRINCIPAL") == 1


# ------------------------- 13/14: CLI preservado + nenhuma chamada nova sem Principal -------------------------

def test_cli_interactive_ask_agent_call_still_has_no_principal():
    src = inspect.getsource(main_module.main)
    assert "ask_agent(user_text)" in src
    assert "ask_agent(user_text, principal" not in src


# ------------------------- 15/16/17: contagem global final + nenhum SERVICE_ fora de escopo -------------------------

def test_exactly_four_service_principal_uses_wired_in_main_module():
    src = inspect.getsource(main_module)
    assert src.count("principal=rbac.SERVICE_MONITOR_PRINCIPAL") == 2
    assert src.count("principal=rbac.SERVICE_RECONCILE_PRINCIPAL") == 1
    assert src.count("principal=rbac.SERVICE_PROACTIVE_AUDIT_PRINCIPAL") == 1
    assert src.count("principal=") == 4  # só os 3 loops automáticos, CLI continua sem


def test_no_other_service_principal_constant_used_in_main_module():
    src = inspect.getsource(main_module)
    used_constants = {
        "SERVICE_MONITOR_PRINCIPAL",
        "SERVICE_RECONCILE_PRINCIPAL",
        "SERVICE_PROACTIVE_AUDIT_PRINCIPAL",
    }
    all_service_names = {
        name for name in dir(rbac) if name.startswith("SERVICE_") and name.endswith("_PRINCIPAL")
    }
    for name in all_service_names - used_constants:
        assert f"rbac.{name}" not in src, f"{name} não deveria ser usado em main.py nesta fase"
