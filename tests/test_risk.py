"""Testes para tools/risk.py — gate de confirmação humana para ações de
alto risco. Usa o banco de dados real (init_db já roda via conftest/outros
testes), sem mockar a camada de persistência."""

import time

import pytest

from database.db import get_pending_action, init_db
from tools import risk


@pytest.fixture(autouse=True)
def _setup_db():
    init_db()
    yield


def test_request_confirmation_creates_pending_row_and_does_not_execute():
    calls = []
    risk.register_action("test_action_a", lambda **kw: calls.append(kw) or "executou")

    msg = risk.request_confirmation("test_action_a", "resumo de teste", value=42)

    assert "AÇÃO DE ALTO RISCO NÃO EXECUTADA" in msg
    assert calls == []  # nada foi executado ainda


def test_confirm_and_execute_runs_the_registered_function():
    calls = []
    risk.register_action("test_action_b", lambda **kw: calls.append(kw) or "ok")

    msg = risk.request_confirmation("test_action_b", "resumo b", x=1, y=2)
    action_id = int(msg.split("id=")[1].split(")")[0])

    result = risk.confirm_and_execute(action_id)

    assert calls == [{"x": 1, "y": 2}]
    assert "confirmada e executada" in result

    row = get_pending_action(action_id)
    assert row[4] == "executada"


def test_confirm_and_execute_twice_fails_second_time():
    risk.register_action("test_action_c", lambda: "ok")
    msg = risk.request_confirmation("test_action_c", "resumo c")
    action_id = int(msg.split("id=")[1].split(")")[0])

    first = risk.confirm_and_execute(action_id)
    second = risk.confirm_and_execute(action_id)

    assert "confirmada e executada" in first
    assert "já está com status 'executada'" in second


def test_cancel_pending_action():
    risk.register_action("test_action_d", lambda: "nunca deveria rodar")
    msg = risk.request_confirmation("test_action_d", "resumo d")
    action_id = int(msg.split("id=")[1].split(")")[0])

    cancel_msg = risk.cancel(action_id)
    assert "cancelada" in cancel_msg

    result = risk.confirm_and_execute(action_id)
    assert "não pode ser executada de novo" in result


def test_confirm_and_execute_expired_action():
    risk.register_action("test_action_e", lambda: "nunca deveria rodar")
    msg = risk.request_confirmation("test_action_e", "resumo e", ttl_minutes=0)
    action_id = int(msg.split("id=")[1].split(")")[0])

    time.sleep(1)
    result = risk.confirm_and_execute(action_id)
    assert "expirou" in result


def test_list_pending_shows_only_active_pending_actions():
    risk.register_action("test_action_f", lambda: "ok")
    msg = risk.request_confirmation("test_action_f", "resumo listável")
    action_id = int(msg.split("id=")[1].split(")")[0])

    listing = risk.list_pending()
    assert f"[{action_id}]" in listing
    assert "resumo listável" in listing

    risk.cancel(action_id)
    listing_after = risk.list_pending()
    assert f"[{action_id}]" not in listing_after
