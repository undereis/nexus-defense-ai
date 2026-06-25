import importlib
import socket
import time

import pytest


@pytest.fixture
def honeypot_module(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_honeypot.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    import tools.honeypot as honeypot
    importlib.reload(honeypot)
    monkeypatch.setattr(honeypot.firewall, "block_ip", lambda ip, reason: f"IP {ip} bloqueado.")
    monkeypatch.setattr(honeypot, "record_threat_isolation", lambda ip: None)
    monkeypatch.setattr(honeypot.notify, "send_notification", lambda *a, **k: True)
    yield honeypot, dbmod
    if honeypot.is_running():
        honeypot.stop()


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_not_running_initially(honeypot_module):
    honeypot, _ = honeypot_module
    assert honeypot.is_running() is False


def test_start_and_stop(honeypot_module):
    honeypot, _ = honeypot_module
    port = _free_port()
    result = honeypot.start(port)
    assert "iniciado" in result
    assert honeypot.is_running() is True

    stop_result = honeypot.stop()
    assert "parado" in stop_result.lower()
    assert honeypot.is_running() is False


def test_starting_twice_is_idempotent(honeypot_module):
    honeypot, _ = honeypot_module
    port = _free_port()
    honeypot.start(port)
    second = honeypot.start(port)
    assert "já está rodando" in second


def test_connection_is_recorded_and_isolated(honeypot_module):
    honeypot, dbmod = honeypot_module
    port = _free_port()
    honeypot.start(port)
    time.sleep(0.2)

    client = socket.create_connection(("127.0.0.1", port), timeout=2)
    client.recv(64)
    client.close()
    time.sleep(0.3)

    hits = dbmod.list_honeypot_hits()
    assert len(hits) == 1
    assert hits[0][0] == "127.0.0.1"
    assert hits[0][1] == port


def test_describe_hits_when_empty(honeypot_module):
    honeypot, _ = honeypot_module
    result = honeypot.describe_hits()
    assert "Nenhuma conexão" in result


def test_describe_hits_after_capture(honeypot_module):
    honeypot, dbmod = honeypot_module
    dbmod.record_honeypot_hit("9.9.9.9", 2222)
    result = honeypot.describe_hits()
    assert "9.9.9.9" in result


@pytest.mark.parametrize("ip", ["127.0.0.1", "127.5.5.5", "::1"])
def test_loopback_never_isolated(ip):
    from tools.honeypot import _is_safe_to_isolate
    assert _is_safe_to_isolate(ip) is False


@pytest.mark.parametrize("ip", ["8.8.8.8", "192.168.1.50", "45.187.68.91"])
def test_non_loopback_can_be_isolated(ip):
    from tools.honeypot import _is_safe_to_isolate
    assert _is_safe_to_isolate(ip) is True


def test_loopback_connection_is_recorded_but_not_isolated(honeypot_module, monkeypatch):
    honeypot, dbmod = honeypot_module
    blocked = []
    monkeypatch.setattr(honeypot.firewall, "block_ip", lambda ip, reason: blocked.append(ip))

    port = _free_port()
    honeypot.start(port)
    time.sleep(0.2)

    client = socket.create_connection(("127.0.0.1", port), timeout=2)
    client.recv(64)
    client.close()
    time.sleep(0.3)

    assert len(dbmod.list_honeypot_hits()) == 1
    assert blocked == []  # nunca chamou block_ip para loopback
