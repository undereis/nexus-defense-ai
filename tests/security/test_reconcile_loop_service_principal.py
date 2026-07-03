"""CP-SD Fase 5B — reconcile_loop (main.py) migrado para Service Principal explícito.

Antes: a única chamada ask_agent dentro de reconcile_loop não passava
`principal=`, então caía no fallback local_admin/admin do ask_agent (Fase 2).
Agora passa `principal=rbac.SERVICE_RECONCILE_PRINCIPAL` (Fase 5A) — mudança de
uma linha, sem alterar periodicidade, payload, lógica de reconcile ou try/except.

monitor_loop e proactive_audit_loop CONTINUAM fora de escopo (não migrados
nesta fase); o loop interativo do CLI continua chamando ask_agent sem
principal de propósito (Fase 2: só o CLI local pode).

Nenhum loop real roda: reconcile_loop é chamado uma vez com um stop_event cujo
`.wait()` já seta o evento (uma iteração só, sem while infinito real). Todas as
dependências (check_and_reconcile/describe/send_notification/log_event/
_announce/ask_agent) são mockadas — nenhum firewall/rede/AbuseIPDB/Mikrotik
real, nenhum agente real, nenhum banco real tocado.
"""

import inspect
import threading

import main as main_module
from core import rbac


class _FakeReconcileResult:
    def __init__(self, has_drift: bool):
        self.has_drift = has_drift


def _run_one_iteration(monkeypatch, *, has_drift: bool):
    """Roda reconcile_loop por EXATAMENTE uma iteração: stop_event.wait() já
    seta o evento na primeira chamada, então o `while not stop_event.is_set()`
    do topo do laço encerra no início da segunda volta — sem while infinito
    real, sem sleep real."""
    captured: dict = {}

    monkeypatch.setattr(
        main_module, "check_and_reconcile",
        lambda auto_reapply=True: _FakeReconcileResult(has_drift),
    )
    monkeypatch.setattr(main_module, "describe", lambda result: "drift fake (teste)")
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

    main_module.reconcile_loop(stop_event)
    return captured


# ------------------------- 1/2/3: chama ask_agent com o Service Principal, sem loop/agente real -------------------------

def test_reconcile_loop_calls_ask_agent_with_service_reconcile_principal(monkeypatch):
    captured = _run_one_iteration(monkeypatch, has_drift=True)
    assert captured["principal"] == rbac.SERVICE_RECONCILE_PRINCIPAL
    assert "drift fake (teste)" in captured["text"]


def test_reconcile_loop_without_drift_does_not_call_ask_agent(monkeypatch):
    """Sem drift, o ramo do ask_agent nem roda — comportamento antigo preservado."""
    captured = _run_one_iteration(monkeypatch, has_drift=False)
    assert captured == {}


# ------------------------- 10: monitor_loop fora de escopo -------------------------
# proactive_audit_loop foi migrado na Fase 5C — ver
# test_proactive_audit_loop_service_principal.py para as asserções sobre ele.

def test_monitor_loop_source_unchanged_no_service_principal():
    src = inspect.getsource(main_module.monitor_loop)
    assert "principal=" not in src
    assert "SERVICE_" not in src


# ------------------------- 12/13: CLI interativo preservado + nenhuma chamada nova sem Principal -------------------------

def test_cli_interactive_ask_agent_call_still_has_no_principal():
    src = inspect.getsource(main_module.main)
    assert "ask_agent(user_text)" in src
    assert "ask_agent(user_text, principal" not in src


def test_reconcile_loop_gained_explicit_principal_in_main_module():
    """reconcile_loop (Fase 5B) tem exatamente uma chamada ask_agent com
    SERVICE_RECONCILE_PRINCIPAL. A contagem GLOBAL de `principal=` em main.py
    (quantos loops já foram migrados) é responsabilidade do teste dedicado de
    cada fase que adiciona um novo loop — ver
    test_proactive_audit_loop_service_principal.py (Fase 5C)."""
    src = inspect.getsource(main_module.reconcile_loop)
    assert src.count("principal=rbac.SERVICE_RECONCILE_PRINCIPAL") == 1
