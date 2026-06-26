"""Testes para tools/risk.py — gate de confirmação humana para ações de
alto risco. Usa o banco de dados real (init_db já roda via conftest/outros
testes), sem mockar a camada de persistência."""

import threading
import time

import pytest

from database.db import get_pending_action, init_db
from tools import risk


@pytest.fixture(autouse=True)
def _setup_db():
    init_db()
    yield


def _extract_id(msg: str) -> int:
    return int(msg.split("id=")[1].split(")")[0])


def _real_code(action_id: int) -> str:
    row = get_pending_action(action_id)
    return row[4]


def test_request_confirmation_creates_pending_row_and_does_not_execute():
    calls = []
    risk.register_action("test_action_a", lambda **kw: calls.append(kw) or "executou")

    msg = risk.request_confirmation("test_action_a", "resumo de teste", value=42)

    assert "AÇÃO DE ALTO RISCO NÃO EXECUTADA" in msg
    assert calls == []  # nada foi executado ainda


def test_confirmation_code_never_appears_in_the_returned_message():
    risk.register_action("test_action_code_leak", lambda: "ok")
    msg = risk.request_confirmation("test_action_code_leak", "resumo sem vazar código")
    action_id = _extract_id(msg)
    real_code = _real_code(action_id)

    assert real_code not in msg


def test_confirm_and_execute_runs_the_registered_function_with_correct_code():
    calls = []
    risk.register_action("test_action_b", lambda **kw: calls.append(kw) or "ok")

    msg = risk.request_confirmation("test_action_b", "resumo b", x=1, y=2)
    action_id = _extract_id(msg)

    result = risk.confirm_and_execute(action_id, _real_code(action_id))

    assert calls == [{"x": 1, "y": 2}]
    assert "confirmada e executada" in result

    row = get_pending_action(action_id)
    assert row[5] == "executada"


def test_confirm_and_execute_wrong_code_does_not_execute():
    calls = []
    risk.register_action("test_action_wrong_code", lambda **kw: calls.append(kw) or "ok")

    msg = risk.request_confirmation("test_action_wrong_code", "resumo código errado")
    action_id = _extract_id(msg)

    result = risk.confirm_and_execute(action_id, "000000")

    assert calls == []
    assert "incorreto" in result
    row = get_pending_action(action_id)
    assert row[5] == "pending"


def test_confirm_and_execute_twice_fails_second_time():
    risk.register_action("test_action_c", lambda: "ok")
    msg = risk.request_confirmation("test_action_c", "resumo c")
    action_id = _extract_id(msg)
    code = _real_code(action_id)

    first = risk.confirm_and_execute(action_id, code)
    second = risk.confirm_and_execute(action_id, code)

    assert "confirmada e executada" in first
    assert "já está com status 'executada'" in second


def test_cancel_pending_action():
    risk.register_action("test_action_d", lambda: "nunca deveria rodar")
    msg = risk.request_confirmation("test_action_d", "resumo d")
    action_id = _extract_id(msg)
    code = _real_code(action_id)

    cancel_msg = risk.cancel(action_id)
    assert "cancelada" in cancel_msg

    result = risk.confirm_and_execute(action_id, code)
    assert "não pode ser executada de novo" in result


def test_confirm_and_execute_expired_action():
    risk.register_action("test_action_e", lambda: "nunca deveria rodar")
    msg = risk.request_confirmation("test_action_e", "resumo e", ttl_minutes=0)
    action_id = _extract_id(msg)
    code = _real_code(action_id)

    time.sleep(1)
    result = risk.confirm_and_execute(action_id, code)
    assert "expirou" in result


def test_request_confirmation_attaches_knowledge_base_reference_when_found():
    from database.db import add_knowledge_document

    unique_term = "zyxwvuabcde9988"
    add_knowledge_document(
        "mikrotik", "RouterOS Firewall Filter Chains de Teste",
        "https://help.mikrotik.com/docs/firewall",
        f"Documentação sobre chain=input action=drop no firewall RouterOS, termo único {unique_term}.",
    )
    risk.register_action("test_action_kb", lambda **kw: "ok")

    msg = risk.request_confirmation("test_action_kb", "resumo com kb", kb_query=unique_term)

    assert "Referência técnica encontrada" in msg
    assert "RouterOS Firewall Filter Chains de Teste" in msg


def test_request_confirmation_without_kb_query_has_no_reference_block():
    risk.register_action("test_action_no_kb", lambda **kw: "ok")
    msg = risk.request_confirmation("test_action_no_kb", "resumo sem kb")
    assert "Referência técnica encontrada" not in msg


def test_sweep_expired_marks_overdue_pending_actions_and_returns_ids():
    risk.register_action("test_action_sweep", lambda: "nunca deveria rodar")
    msg = risk.request_confirmation("test_action_sweep", "resumo sweep", ttl_minutes=0)
    action_id = _extract_id(msg)
    code = _real_code(action_id)

    time.sleep(1)
    expired_ids = risk.sweep_expired()

    assert action_id in expired_ids
    row = get_pending_action(action_id)
    assert row[5] == "expirada"

    # depois de expirada pela varredura, confirmar não executa mais
    result = risk.confirm_and_execute(action_id, code)
    assert "já está com status 'expirada'" in result


def test_sweep_expired_does_not_touch_active_pending_actions():
    risk.register_action("test_action_not_expired", lambda: "ok")
    msg = risk.request_confirmation("test_action_not_expired", "resumo ainda válido", ttl_minutes=10)
    action_id = _extract_id(msg)

    expired_ids = risk.sweep_expired()

    assert action_id not in expired_ids
    row = get_pending_action(action_id)
    assert row[5] == "pending"


def test_confirm_and_execute_uses_timing_safe_comparison(monkeypatch):
    """Garante que a checagem do código passa por secrets.compare_digest,
    não por != direto — regressão do achado de timing attack."""
    calls = []
    monkeypatch.setattr(
        risk.secrets, "compare_digest", lambda a, b: calls.append((a, b)) or (a == b)
    )
    risk.register_action("test_action_timing", lambda: "ok")
    msg = risk.request_confirmation("test_action_timing", "resumo timing")
    action_id = _extract_id(msg)

    risk.confirm_and_execute(action_id, _real_code(action_id))

    assert len(calls) == 1


def test_concurrent_confirmations_with_correct_code_execute_only_once():
    """Regressão da race condition: duas threads confirmando a mesma ação
    ao mesmo tempo, com o código correto, só uma deve conseguir executar
    a função registrada — a outra deve ver que já foi resolvida."""
    call_count = {"n": 0}
    lock = threading.Lock()

    def slow_action():
        # Simula trabalho real (ex: chamada SSH/API) para alargar a janela
        # de corrida entre as duas threads.
        time.sleep(0.05)
        with lock:
            call_count["n"] += 1
        return "ok"

    risk.register_action("test_action_concurrent", slow_action)
    msg = risk.request_confirmation("test_action_concurrent", "resumo concorrente")
    action_id = _extract_id(msg)
    code = _real_code(action_id)

    results = []

    def attempt():
        results.append(risk.confirm_and_execute(action_id, code))

    threads = [threading.Thread(target=attempt) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert call_count["n"] == 1, "a função registrada não pode rodar mais de uma vez"
    successes = [r for r in results if "confirmada e executada" in r]
    assert len(successes) == 1


def test_confirm_and_execute_marks_failed_when_action_raises():
    def boom():
        raise RuntimeError("falha simulada de execução real")

    risk.register_action("test_action_raises", boom)
    msg = risk.request_confirmation("test_action_raises", "resumo que falha")
    action_id = _extract_id(msg)

    result = risk.confirm_and_execute(action_id, _real_code(action_id))

    assert "falhou" in result.lower()
    row = get_pending_action(action_id)
    assert row[5] == "falhou"

    # auditoria não pode dizer 'executada' para uma ação que nunca rodou de fato
    second = risk.confirm_and_execute(action_id, _real_code(action_id))
    assert "não pode ser executada de novo" in second


def test_list_pending_shows_only_active_pending_actions():
    risk.register_action("test_action_f", lambda: "ok")
    msg = risk.request_confirmation("test_action_f", "resumo listável")
    action_id = _extract_id(msg)

    listing = risk.list_pending()
    assert f"[{action_id}]" in listing
    assert "resumo listável" in listing

    risk.cancel(action_id)
    listing_after = risk.list_pending()
    assert f"[{action_id}]" not in listing_after
