import importlib

import pytest


@pytest.fixture
def watchdog_module(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_watchdog.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    import tools.watchdog as watchdog
    importlib.reload(watchdog)
    yield watchdog


def test_expected_services_empty_when_disabled(watchdog_module, monkeypatch):
    import config
    monkeypatch.setattr(config, "HONEYPOT_ENABLED", False)
    monkeypatch.setattr(watchdog_module, "HONEYPOT_ENABLED", False)
    assert watchdog_module.expected_services() == []


def test_expected_services_parses_list(watchdog_module, monkeypatch):
    monkeypatch.setattr(watchdog_module, "HONEYPOT_ENABLED", True)
    monkeypatch.setattr(watchdog_module, "HONEYPOT_SERVICES", "ssh:2222,ftp:2121,http:8081")
    result = watchdog_module.expected_services()
    assert result == [("ssh", 2222), ("ftp", 2121), ("http", 8081)]


def test_expected_services_ignores_malformed_entries(watchdog_module, monkeypatch):
    monkeypatch.setattr(watchdog_module, "HONEYPOT_ENABLED", True)
    monkeypatch.setattr(watchdog_module, "HONEYPOT_SERVICES", "ssh:2222,malformado,ftp:abc,http:8081")
    result = watchdog_module.expected_services()
    assert result == [("ssh", 2222), ("http", 8081)]


def test_check_and_heal_does_nothing_when_disabled(watchdog_module, monkeypatch):
    monkeypatch.setattr(watchdog_module, "HONEYPOT_ENABLED", False)
    assert watchdog_module.check_and_heal() == []


def test_check_and_heal_restarts_missing_service(watchdog_module, monkeypatch):
    monkeypatch.setattr(watchdog_module, "HONEYPOT_ENABLED", True)
    monkeypatch.setattr(watchdog_module, "HONEYPOT_SERVICES", "ssh:2222")
    monkeypatch.setattr(watchdog_module.honeypot, "list_running", lambda: [])

    started = []
    monkeypatch.setattr(
        watchdog_module.honeypot, "start", lambda s, p: started.append((s, p)) or f"{s} iniciado na porta {p}"
    )
    notified = []
    monkeypatch.setattr(watchdog_module.notify, "send_notification", lambda *a, **k: notified.append(a) or True)

    healed = watchdog_module.check_and_heal()
    assert healed == ["ssh:2222"]
    assert started == [("ssh", 2222)]
    assert len(notified) == 1


def test_check_and_heal_does_nothing_when_all_running(watchdog_module, monkeypatch):
    monkeypatch.setattr(watchdog_module, "HONEYPOT_ENABLED", True)
    monkeypatch.setattr(watchdog_module, "HONEYPOT_SERVICES", "ssh:2222,ftp:2121")
    monkeypatch.setattr(watchdog_module.honeypot, "list_running", lambda: [("ssh", 2222), ("ftp", 2121)])

    started = []
    monkeypatch.setattr(watchdog_module.honeypot, "start", lambda s, p: started.append((s, p)) or f"{s} iniciado na porta {p}")

    healed = watchdog_module.check_and_heal()
    assert healed == []
    assert started == []


def test_check_and_heal_only_restarts_the_missing_one(watchdog_module, monkeypatch):
    monkeypatch.setattr(watchdog_module, "HONEYPOT_ENABLED", True)
    monkeypatch.setattr(watchdog_module, "HONEYPOT_SERVICES", "ssh:2222,ftp:2121")
    monkeypatch.setattr(watchdog_module.honeypot, "list_running", lambda: [("ssh", 2222)])

    started = []
    monkeypatch.setattr(watchdog_module.honeypot, "start", lambda s, p: started.append((s, p)) or f"{s} iniciado na porta {p}")
    monkeypatch.setattr(watchdog_module.notify, "send_notification", lambda *a, **k: True)

    healed = watchdog_module.check_and_heal()
    assert healed == ["ftp:2121"]
    assert started == [("ftp", 2121)]


def test_check_and_heal_respects_manually_stopped_service(watchdog_module, monkeypatch):
    """Regressão: watchdog ressuscitando honeypot que o criador parou de
    propósito via stop() — não deve, mesmo que esteja em HONEYPOT_SERVICES."""
    monkeypatch.setattr(watchdog_module, "HONEYPOT_ENABLED", True)
    monkeypatch.setattr(watchdog_module, "HONEYPOT_SERVICES", "ssh:2222,ftp:2121")
    monkeypatch.setattr(watchdog_module.honeypot, "list_running", lambda: [])
    monkeypatch.setattr(
        watchdog_module.honeypot, "is_manually_stopped",
        lambda service, port: (service, port) == ("ssh", 2222),
    )

    started = []
    monkeypatch.setattr(watchdog_module.honeypot, "start", lambda s, p: started.append((s, p)) or f"{s} iniciado na porta {p}")
    monkeypatch.setattr(watchdog_module.notify, "send_notification", lambda *a, **k: True)

    healed = watchdog_module.check_and_heal()

    assert healed == ["ftp:2121"]
    assert ("ssh", 2222) not in started
