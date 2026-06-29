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


# ---------- webhook bidirecional (helpers puros) ----------

def test_webhook_secret_ok(monkeypatch):
    monkeypatch.setattr(telegram, "TELEGRAM_WEBHOOK_SECRET", "s3cr3t")
    assert telegram.webhook_secret_ok("s3cr3t") is True
    assert telegram.webhook_secret_ok("errado") is False
    assert telegram.webhook_secret_ok(None) is False


def test_webhook_secret_unset_always_false(monkeypatch):
    monkeypatch.setattr(telegram, "TELEGRAM_WEBHOOK_SECRET", "")
    assert telegram.webhook_secret_ok("qualquer") is False


def test_is_authorized_chat(monkeypatch):
    monkeypatch.setattr(telegram, "TELEGRAM_CHAT_ID", "-100777")
    assert telegram.is_authorized_chat(-100777) is True   # int vindo do Telegram
    assert telegram.is_authorized_chat("-100777") is True
    assert telegram.is_authorized_chat(999) is False


def test_webhook_configured(monkeypatch):
    monkeypatch.setattr(telegram, "TELEGRAM_BOT_TOKEN", "123:abc")
    monkeypatch.setattr(telegram, "TELEGRAM_CHAT_ID", "-100")
    monkeypatch.setattr(telegram, "TELEGRAM_WEBHOOK_SECRET", "")
    assert telegram.webhook_configured() is False
    monkeypatch.setattr(telegram, "TELEGRAM_WEBHOOK_SECRET", "s")
    assert telegram.webhook_configured() is True


def test_parse_update_message():
    upd = {"message": {"text": " oi ", "chat": {"id": -100777}, "from": {"id": 42}}}
    assert telegram.parse_update(upd) == {"chat_id": -100777, "text": "oi", "from_id": 42}


def test_parse_update_edited_message():
    upd = {"edited_message": {"text": "x", "chat": {"id": 5}}}
    assert telegram.parse_update(upd)["chat_id"] == 5


def test_parse_update_non_text_is_none():
    assert telegram.parse_update({"message": {"photo": [], "chat": {"id": 5}}}) is None
    assert telegram.parse_update({"message": {"text": "", "chat": {"id": 5}}}) is None
    assert telegram.parse_update({}) is None


def test_normalize_command():
    assert telegram.normalize_command("/status@NexusBot agora") == "status agora"
    assert telegram.normalize_command("/block c1") == "block c1"
    assert telegram.normalize_command("qual o status?") == "qual o status?"
    assert telegram.normalize_command("/devices") == "devices"


def test_send_telegram_to_posts_to_given_chat(monkeypatch):
    monkeypatch.setattr(telegram, "TELEGRAM_BOT_TOKEN", "123:abc")
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["json"] = json
        return _FakeResp(200, {"ok": True})

    monkeypatch.setattr(telegram.requests, "post", fake_post)
    assert telegram.send_telegram_to(-100888, "resposta") is True
    assert captured["json"]["chat_id"] == -100888
    assert captured["json"]["text"] == "resposta"


def test_set_webhook_requires_https(monkeypatch):
    monkeypatch.setattr(telegram, "TELEGRAM_BOT_TOKEN", "123:abc")
    monkeypatch.setattr(telegram, "TELEGRAM_WEBHOOK_SECRET", "s3cr3t")
    out = telegram.set_webhook("http://inseguro/telegram/webhook")
    assert "HTTPS" in out


def test_set_webhook_registers_with_secret(monkeypatch):
    monkeypatch.setattr(telegram, "TELEGRAM_BOT_TOKEN", "123:abc")
    monkeypatch.setattr(telegram, "TELEGRAM_WEBHOOK_SECRET", "s3cr3t")
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return _FakeResp(200, {"ok": True})

    monkeypatch.setattr(telegram.requests, "post", fake_post)
    out = telegram.set_webhook("https://noc.x/telegram/webhook")
    assert "sucesso" in out.lower()
    assert captured["url"].endswith("/setWebhook")
    assert captured["json"]["secret_token"] == "s3cr3t"
    assert captured["json"]["url"] == "https://noc.x/telegram/webhook"


def test_set_webhook_unconfigured(monkeypatch):
    monkeypatch.setattr(telegram, "TELEGRAM_BOT_TOKEN", "")
    assert "não configurado" in telegram.set_webhook("https://x/telegram/webhook")


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
