"""Testes do canal de notificação Telegram (Fase 8).

Cobre: não-configurado → False sem rede; envio quando configurado; nunca
levanta exceção (falha de rede ou ok=false viram False); e o roteamento do
notify.send_notification para o Telegram quando habilitado.
"""

import requests

from tools import notify, telegram


class _FakeResp:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def test_not_configured_returns_false_without_network(monkeypatch):
    monkeypatch.setattr(telegram, "TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setattr(telegram, "TELEGRAM_CHAT_ID", "")

    def boom(*a, **k):  # garante que nem tenta rede
        raise AssertionError("não deveria chamar requests.post sem configuração")

    monkeypatch.setattr(telegram.requests, "post", boom)
    assert telegram.is_configured() is False
    assert telegram.send_telegram("oi") is False


def test_sends_when_configured(monkeypatch):
    monkeypatch.setattr(telegram, "TELEGRAM_BOT_TOKEN", "123:abc")
    monkeypatch.setattr(telegram, "TELEGRAM_CHAT_ID", "-100999")
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return _FakeResp(200, {"ok": True, "result": {}})

    monkeypatch.setattr(telegram.requests, "post", fake_post)
    assert telegram.send_telegram("mensagem") is True
    assert "bot123:abc/sendMessage" in captured["url"]
    assert captured["json"]["chat_id"] == "-100999"
    assert captured["json"]["text"] == "mensagem"


def test_api_not_ok_returns_false(monkeypatch):
    monkeypatch.setattr(telegram, "TELEGRAM_BOT_TOKEN", "123:abc")
    monkeypatch.setattr(telegram, "TELEGRAM_CHAT_ID", "-100")
    monkeypatch.setattr(
        telegram.requests, "post",
        lambda *a, **k: _FakeResp(200, {"ok": False, "error_code": 403}),
    )
    assert telegram.send_telegram("x") is False


def test_never_raises_on_network_error(monkeypatch):
    monkeypatch.setattr(telegram, "TELEGRAM_BOT_TOKEN", "123:abc")
    monkeypatch.setattr(telegram, "TELEGRAM_CHAT_ID", "-100")

    def boom(*a, **k):
        raise requests.RequestException("rede caiu")

    monkeypatch.setattr(telegram.requests, "post", boom)
    assert telegram.send_telegram("x") is False


def test_notify_routes_to_telegram(monkeypatch):
    """send_notification deve usar o Telegram como canal adicional quando
    Slack/webhook estão desligados e o Telegram está configurado."""
    monkeypatch.setattr(notify, "SLACK_BOT_TOKEN", "")
    monkeypatch.setattr(notify, "SLACK_CHANNEL_ID", "")
    monkeypatch.setattr(notify, "NOTIFY_WEBHOOK_URL", "")
    monkeypatch.setattr(telegram, "TELEGRAM_BOT_TOKEN", "123:abc")
    monkeypatch.setattr(telegram, "TELEGRAM_CHAT_ID", "-100")
    sent = []
    monkeypatch.setattr(telegram, "send_telegram", lambda text: sent.append(text) or True)

    assert notify.send_notification("Titulo", "Corpo") is True
    assert sent and "Titulo" in sent[0] and "Corpo" in sent[0]
