"""CP-SD Fase 5C — proactive_audit_loop (main.py) migrado para Service Principal explícito.

Antes: a única chamada ask_agent dentro de proactive_audit_loop não passava
`principal=`, então caía no fallback local_admin/admin do ask_agent (Fase 2).
Agora passa `principal=rbac.SERVICE_PROACTIVE_AUDIT_PRINCIPAL` (Fase 5A) —
mudança de uma linha, sem alterar periodicidade, payload, lógica de auditoria
proativa ou try/except. Segue o mesmo padrão da Fase 5B (reconcile_loop).

monitor_loop continua fora de escopo (2 chamadas ask_agent sem Principal,
dívida rastreada); reconcile_loop mantém SERVICE_RECONCILE_PRINCIPAL (Fase
5B); o loop interativo do CLI continua chamando ask_agent sem principal de
propósito (Fase 2: só o CLI local pode).

Nenhum loop real roda: proactive_audit_loop é chamado uma vez com um
stop_event cujo `.wait()` já seta o evento (uma iteração só, sem while
infinito real). Todas as dependências (get_due_assets/check_asset/
send_notification/log_event/_announce/ask_agent) são mockadas — nenhum
firewall/rede/AbuseIPDB/Mikrotik real, nenhum agente real, nenhum banco real
tocado.
"""

import inspect
import threading

import main as main_module
from core import rbac


def _run_one_iteration(monkeypatch, *, changed: bool):
    """Roda proactive_audit_loop por EXATAMENTE uma iteração: stop_event.wait()
    já seta o evento na primeira chamada, então o `while not stop_event.is_set()`
    do topo do laço encerra no início da segunda volta — sem while infinito
    real, sem sleep real."""
    captured: dict = {}

    monkeypatch.setattr(main_module, "get_due_assets", lambda: ["host-fake.local"])
    monkeypatch.setattr(
        main_module, "check_asset", lambda host: (changed, "resumo fake (teste)")
    )
    monkeypatch.setattr(main_module, "send_notification", lambda *a, **k: None)
    monkeypatch.setattr(main_module, "log_event", lambda *a, **k: None)
    monkeypatch.setattr(main_module, "_announce", lambda *a, **k: None)

    def _fake_ask_agent(text, principal=None):
        captured["text"] = text
        captured["principal"] = principal
        return "ok (fake)"

    monkeypatch.setattr(main_module, "ask_agent", _fake_ask_agent)

    stop_event = threading.Event()
    monkeypatch.setattr(stop_event, "wait", lambda timeout=None: stop_event.set())

    main_module.proactive_audit_loop(stop_event)
    return captured


# ------------------------- 1/2/3: chama ask_agent com o Service Principal, sem loop/agente real -------------------------

def test_proactive_audit_loop_calls_ask_agent_with_service_principal(monkeypatch):
    captured = _run_one_iteration(monkeypatch, changed=True)
    assert captured["principal"] == rbac.SERVICE_PROACTIVE_AUDIT_PRINCIPAL
    assert "resumo fake (teste)" in captured["text"]
    assert "host-fake.local" in captured["text"]


def test_proactive_audit_loop_without_change_does_not_call_ask_agent(monkeypatch):
    """Sem mudança detectada, o ramo do ask_agent nem roda — comportamento
    antigo preservado."""
    captured = _run_one_iteration(monkeypatch, changed=False)
    assert captured == {}


# ------------------------- 10/15: monitor_loop fora de escopo, 2 chamadas sem Principal -------------------------

def test_monitor_loop_source_unchanged_no_service_principal():
    src = inspect.getsource(main_module.monitor_loop)
    assert "principal=" not in src
    assert "SERVICE_" not in src


def test_monitor_loop_still_has_two_ask_agent_calls_without_principal():
    src = inspect.getsource(main_module.monitor_loop)
    assert src.count("ask_agent(") == 2


# ------------------------- 11: reconcile_loop mantém seu Service Principal -------------------------

def test_reconcile_loop_still_uses_service_reconcile_principal():
    src = inspect.getsource(main_module.reconcile_loop)
    assert "principal=rbac.SERVICE_RECONCILE_PRINCIPAL" in src


# ------------------------- 12/13/14: CLI preservado + contagem global -------------------------

def test_cli_interactive_ask_agent_call_still_has_no_principal():
    src = inspect.getsource(main_module.main)
    assert "ask_agent(user_text)" in src
    assert "ask_agent(user_text, principal" not in src


def test_exactly_two_service_principals_wired_in_main_module():
    src = inspect.getsource(main_module)
    assert src.count("principal=rbac.SERVICE_RECONCILE_PRINCIPAL") == 1
    assert src.count("principal=rbac.SERVICE_PROACTIVE_AUDIT_PRINCIPAL") == 1
    assert src.count("principal=") == 2  # só reconcile_loop + proactive_audit_loop
