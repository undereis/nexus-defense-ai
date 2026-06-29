"""Testes do monitor de equipamentos (Fase 8 — tools/device_monitor.py).

Cobre: abertura de chamado + notificação na queda, baixa + notificação na
recuperação, ausência de re-notificação em estado estável (estado persistido
no DB, não em memória), a primeira observação saudável sem alarme, e ping de
IP inválido sem levantar exceção.

O ping é mockado (object-form monkeypatch em device_monitor.ping); nenhum
ping de rede real é disparado nos casos de transição.
"""

import pytest

import database.db as db_module
from tools import device_monitor


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    db_module.init_db()
    yield


@pytest.fixture
def captured_notify(monkeypatch):
    sent = []
    monkeypatch.setattr(
        device_monitor.notify, "send_notification",
        lambda title, message: sent.append((title, message)) or True,
    )
    return sent


def _set_ping(monkeypatch, online: bool):
    monkeypatch.setattr(device_monitor, "ping", lambda ip, **kw: online)


def test_down_opens_outage_and_notifies(monkeypatch, captured_notify):
    db_module.add_monitored_device("d1", "10.0.0.1", name="OLT-1", type="olt")
    _set_ping(monkeypatch, False)

    transitions = device_monitor.check_all_devices()

    assert transitions == ["DOWN d1 (10.0.0.1)"]
    assert db_module.get_monitored_device("d1")[7] == "offline"  # current_status
    assert db_module.list_device_outages("aberto")  # chamado aberto
    assert len(captured_notify) == 1 and "CAIU" in captured_notify[0][0]


def test_recovery_resolves_and_notifies(monkeypatch, captured_notify):
    db_module.add_monitored_device("d1", "10.0.0.1", name="OLT-1")
    db_module.set_device_status("d1", "offline")
    db_module.open_device_outage("d1", "10.0.0.1", "OLT-1", "queda anterior")
    _set_ping(monkeypatch, True)

    transitions = device_monitor.check_all_devices()

    assert transitions == ["UP d1 (10.0.0.1)"]
    assert db_module.get_monitored_device("d1")[7] == "online"
    assert db_module.list_device_outages("aberto") == []  # baixado
    assert len(captured_notify) == 1 and "VOLTOU" in captured_notify[0][0]


def test_stable_does_not_renotify(monkeypatch, captured_notify):
    db_module.add_monitored_device("d1", "10.0.0.1")
    _set_ping(monkeypatch, False)

    device_monitor.check_all_devices()  # unknown -> offline: notifica
    device_monitor.check_all_devices()  # offline -> offline: nada
    device_monitor.check_all_devices()

    assert len(captured_notify) == 1  # uma única notificação de queda


def test_state_persists_across_calls(monkeypatch, captured_notify):
    """O estado fica no DB: depois de marcar offline, uma nova checagem com o
    mesmo resultado não re-notifica — mesmo simulando um 'restart' (não há
    estado em memória que se perca)."""
    db_module.add_monitored_device("d1", "10.0.0.1")
    _set_ping(monkeypatch, False)
    device_monitor.check_all_devices()
    assert len(captured_notify) == 1
    assert db_module.get_monitored_device("d1")[7] == "offline"

    # "restart": novo ciclo, ping ainda offline → estado lido do DB, sem alarme novo
    device_monitor.check_all_devices()
    assert len(captured_notify) == 1


def test_first_healthy_observation_no_alarm(monkeypatch, captured_notify):
    db_module.add_monitored_device("d1", "10.0.0.1")
    _set_ping(monkeypatch, True)

    transitions = device_monitor.check_all_devices()

    assert transitions == []  # unknown -> online não é alarme
    assert db_module.get_monitored_device("d1")[7] == "online"
    assert captured_notify == []


def test_disabled_device_skipped(monkeypatch, captured_notify):
    db_module.add_monitored_device("d1", "10.0.0.1", enabled=False)
    _set_ping(monkeypatch, False)

    transitions = device_monitor.check_all_devices()
    assert transitions == []
    assert captured_notify == []


def test_ping_invalid_ip_is_false_without_raise():
    assert device_monitor.ping("nao-e-um-ip") is False
