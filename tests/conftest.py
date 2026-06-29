"""Configuração compartilhada da suíte.

Isolamento do canal Telegram: tools/notify passou a enviar TAMBÉM via Telegram
quando configurado (Fase 8). Como o .env real pode ter um TELEGRAM_BOT_TOKEN
de verdade, sem isto um teste que chame notify.send_notification sem mock
dispararia uma chamada REAL à API do Telegram (com o token real) — lento,
com efeito colateral e risco de vazar o token em logs.

Este fixture autouse zera a config do Telegram ANTES de cada teste. Os testes
que QUEREM exercitar o Telegram (test_telegram*, etc.) setam essas mesmas
variáveis no corpo/numa fixture própria, que roda depois e sobrescreve — então
continuam funcionando.
"""

import pytest


@pytest.fixture(autouse=True)
def _isolate_telegram(monkeypatch):
    from tools import telegram

    monkeypatch.setattr(telegram, "TELEGRAM_BOT_TOKEN", "", raising=False)
    monkeypatch.setattr(telegram, "TELEGRAM_CHAT_ID", "", raising=False)
    monkeypatch.setattr(telegram, "TELEGRAM_WEBHOOK_SECRET", "", raising=False)
