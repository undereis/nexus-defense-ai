"""Testes do endpoint de webhook do Telegram (Frente B — NOC bidirecional).

Cobre as duas barreiras de segurança (secret token + chat_id autorizado), a
recusa quando não configurado, e o roteamento de um comando autorizado ao
agente com resposta pelo Telegram. ask_agent e o envio são mockados — nenhum
agente real é construído e nenhuma mensagem real é enviada.
"""

import pytest
from fastapi.testclient import TestClient

import api.server as server
import database.db as db_module
from tools import telegram


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    db_module.init_db()
    yield


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(telegram, "TELEGRAM_BOT_TOKEN", "123:abc")
    monkeypatch.setattr(telegram, "TELEGRAM_CHAT_ID", "-100777")
    monkeypatch.setattr(telegram, "TELEGRAM_WEBHOOK_SECRET", "s3cr3t")


@pytest.fixture
def client():
    return TestClient(server.app)


_HDR = "X-Telegram-Bot-Api-Secret-Token"


def _msg(text, chat_id=-100777, from_id=42):
    return {"message": {"text": text, "chat": {"id": chat_id}, "from": {"id": from_id}}}


def test_not_configured_returns_503(monkeypatch, client):
    monkeypatch.setattr(telegram, "TELEGRAM_WEBHOOK_SECRET", "")
    r = client.post("/telegram/webhook", json=_msg("/status"), headers={_HDR: "x"})
    assert r.status_code == 503


def test_wrong_secret_rejected(configured, client):
    r = client.post("/telegram/webhook", json=_msg("/status"), headers={_HDR: "errado"})
    assert r.status_code == 401


def test_unauthorized_chat_ignored(configured, client, monkeypatch):
    called, sent = [], []
    monkeypatch.setattr(server, "ask_agent", lambda t: called.append(t) or "resp")
    monkeypatch.setattr(telegram, "send_telegram_to", lambda cid, t: sent.append((cid, t)) or True)

    r = client.post("/telegram/webhook", json=_msg("/block c1", chat_id=999),
                    headers={_HDR: "s3cr3t"})

    assert r.status_code == 200
    assert called == []  # não roteou ao agente
    assert sent == []    # não respondeu
    # registrou a tentativa não autorizada
    with db_module.get_conn() as conn:
        types = [row[0] for row in conn.execute("SELECT event_type FROM events").fetchall()]
    assert "telegram_unauthorized" in types


def test_authorized_command_dispatched_and_answered(configured, client, monkeypatch):
    sent = []
    monkeypatch.setattr(server, "ask_agent", lambda t: f"eco:{t}")
    monkeypatch.setattr(telegram, "send_telegram_to", lambda cid, t: sent.append((cid, t)) or True)

    r = client.post("/telegram/webhook", json=_msg("/status@NexusBot agora"),
                    headers={_HDR: "s3cr3t"})

    assert r.status_code == 200
    # normalize_command tirou a barra e o @bot; resposta foi ao chat autorizado
    assert sent == [(-100777, "eco:status agora")]


def test_non_text_update_ignored(configured, client, monkeypatch):
    sent = []
    monkeypatch.setattr(server, "ask_agent", lambda t: "resp")
    monkeypatch.setattr(telegram, "send_telegram_to", lambda cid, t: sent.append((cid, t)) or True)

    r = client.post("/telegram/webhook",
                    json={"message": {"chat": {"id": -100777}, "photo": []}},
                    headers={_HDR: "s3cr3t"})

    assert r.status_code == 200
    assert sent == []
