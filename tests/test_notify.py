import importlib

import pytest
import requests


@pytest.fixture
def notify_module(monkeypatch):
    import config
    monkeypatch.setattr(config, "NOTIFY_WEBHOOK_URL", "https://example.com/webhook")
    monkeypatch.setattr(config, "NOTIFY_WEBHOOK_FORMAT", "slack")
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "")
    import tools.notify as notify
    importlib.reload(notify)
    yield notify
    importlib.reload(notify)  # restaura estado padrão para outros testes


@pytest.fixture
def slack_api_module(monkeypatch):
    import config
    monkeypatch.setattr(config, "NOTIFY_WEBHOOK_URL", "")
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-fake-token")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "C0123456789")
    import tools.notify as notify
    importlib.reload(notify)
    yield notify
    importlib.reload(notify)


def test_not_configured_returns_false(monkeypatch):
    import config
    monkeypatch.setattr(config, "NOTIFY_WEBHOOK_URL", "")
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "")
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


def test_slack_api_used_when_configured(slack_api_module, monkeypatch):
    calls = []

    class FakeResp:
        status_code = 200
        def json(self):
            return {"ok": True}

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResp()

    monkeypatch.setattr(slack_api_module.requests, "post", fake_post)
    assert slack_api_module.send_notification("Alerta", "mensagem") is True
    assert calls[0][0] == "https://slack.com/api/chat.postMessage"
    assert calls[0][1]["headers"]["Authorization"] == "Bearer xoxb-fake-token"
    assert calls[0][1]["json"]["channel"] == "C0123456789"


def test_slack_api_ok_false_is_treated_as_failure(slack_api_module, monkeypatch):
    class FakeResp:
        status_code = 200
        def json(self):
            return {"ok": False, "error": "channel_not_found"}

    monkeypatch.setattr(slack_api_module.requests, "post", lambda *a, **k: FakeResp())
    assert slack_api_module.send_notification("t", "m") is False


def test_is_configured_true_for_slack_api(slack_api_module):
    assert slack_api_module.is_configured() is True


def test_slack_api_failure_falls_back_to_webhook(monkeypatch):
    import config
    monkeypatch.setattr(config, "SLACK_BOT_TOKEN", "xoxb-fake")
    monkeypatch.setattr(config, "SLACK_CHANNEL_ID", "C0123456789")
    monkeypatch.setattr(config, "NOTIFY_WEBHOOK_URL", "https://example.com/webhook")
    monkeypatch.setattr(config, "NOTIFY_WEBHOOK_FORMAT", "slack")
    import tools.notify as notify
    importlib.reload(notify)

    calls = []

    def fake_post(url, **kwargs):
        calls.append(url)
        class FakeResp:
            status_code = 200 if "example.com" in url else 500
            def json(self):
                return {"ok": False}
        return FakeResp()

    monkeypatch.setattr(notify.requests, "post", fake_post)
    assert notify.send_notification("t", "m") is True
    assert calls == ["https://slack.com/api/chat.postMessage", "https://example.com/webhook"]
    importlib.reload(notify)
