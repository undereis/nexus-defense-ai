import importlib

import pytest
import requests


@pytest.fixture
def notify_module(monkeypatch):
    import config
    monkeypatch.setattr(config, "NOTIFY_WEBHOOK_URL", "https://example.com/webhook")
    monkeypatch.setattr(config, "NOTIFY_WEBHOOK_FORMAT", "slack")
    import tools.notify as notify
    importlib.reload(notify)
    yield notify
    importlib.reload(notify)  # restaura estado padrão para outros testes


def test_not_configured_returns_false(monkeypatch):
    import config
    monkeypatch.setattr(config, "NOTIFY_WEBHOOK_URL", "")
    import tools.notify as notify
    importlib.reload(notify)
    assert notify.is_configured() is False
    assert notify.send_notification("titulo", "msg") is False
    importlib.reload(notify)


def test_slack_payload_format(notify_module):
    payload = notify_module._build_payload("Alerta", "algo aconteceu")
    assert payload == {"text": "*Alerta*\nalgo aconteceu"}


def test_discord_payload_format(monkeypatch):
    import config
    monkeypatch.setattr(config, "NOTIFY_WEBHOOK_FORMAT", "discord")
    monkeypatch.setattr(config, "NOTIFY_WEBHOOK_URL", "https://example.com/webhook")
    import tools.notify as notify
    importlib.reload(notify)
    payload = notify._build_payload("Alerta", "algo")
    assert payload == {"content": "*Alerta*\nalgo"}
    importlib.reload(notify)


def test_raw_payload_format(monkeypatch):
    import config
    monkeypatch.setattr(config, "NOTIFY_WEBHOOK_FORMAT", "raw")
    monkeypatch.setattr(config, "NOTIFY_WEBHOOK_URL", "https://example.com/webhook")
    import tools.notify as notify
    importlib.reload(notify)
    payload = notify._build_payload("Alerta", "algo")
    assert payload == {"title": "Alerta", "message": "algo"}
    importlib.reload(notify)


def test_send_notification_success(notify_module, monkeypatch):
    class FakeResp:
        status_code = 200

    monkeypatch.setattr(notify_module.requests, "post", lambda *a, **k: FakeResp())
    assert notify_module.send_notification("t", "m") is True


def test_send_notification_http_error(notify_module, monkeypatch):
    class FakeResp:
        status_code = 500

    monkeypatch.setattr(notify_module.requests, "post", lambda *a, **k: FakeResp())
    assert notify_module.send_notification("t", "m") is False


def test_send_notification_network_failure_does_not_raise(notify_module, monkeypatch):
    def raise_error(*a, **k):
        raise requests.RequestException("boom")

    monkeypatch.setattr(notify_module.requests, "post", raise_error)
    assert notify_module.send_notification("t", "m") is False
