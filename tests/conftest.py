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

import os
from pathlib import Path
import tempfile

import pytest


# Testes que validam ações permitidas esperam explicitamente o modo real, mas
# toda integração externa é mockada pelas próprias suítes. O produto, fora do
# pytest, inicia em `lab`. Um token determinístico impede que a API dependa de
# segredos reais ou de geração/impressão de token durante a coleta.
os.environ["NEXUS_SECRETS_BACKEND"] = "env"
os.environ["NEXUS_API_TOKEN"] = "nexus-test-admin-token-not-for-production"
os.environ["NEXUS_OPERATING_MODE"] = "real"
os.environ["HONEYPOT_CREDENTIAL_KEY"] = (
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)

# A suíte nunca lê nem altera o banco operacional do desenvolvedor. A troca é
# feita antes de os módulos de aplicação serem importados durante a coleta.
_TEST_DATABASE_DIR = tempfile.TemporaryDirectory(prefix="nexus-tests-")
import config  # noqa: E402

config.DB_PATH = Path(_TEST_DATABASE_DIR.name) / "nexus.db"

from database.db import init_db  # noqa: E402

init_db()


@pytest.fixture(autouse=True)
def _isolate_telegram(monkeypatch):
    from tools import telegram

    monkeypatch.setattr(telegram, "TELEGRAM_BOT_TOKEN", "", raising=False)
    monkeypatch.setattr(telegram, "TELEGRAM_CHAT_ID", "", raising=False)
    monkeypatch.setattr(telegram, "TELEGRAM_WEBHOOK_SECRET", "", raising=False)
