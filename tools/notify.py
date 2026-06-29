"""Notificações fora do terminal.

Tudo que a Nexus decide e age sozinha (auto-isolamento, drift de
firewall, mudança em auditoria proativa) até aqui só chegava a você se
o terminal estivesse aberto na sua frente. Isso envia o mesmo aviso
para fora da máquina, por dois caminhos possíveis:

1. Slack Web API (chat.postMessage), se SLACK_BOT_TOKEN + SLACK_CHANNEL_ID
   estiverem configurados — preferido, porque é o canal "oficial" do bot.
2. Webhook genérico (Slack incoming webhook, Discord, custom), se
   NOTIFY_WEBHOOK_URL estiver configurado — usado como alternativa/fallback.

Nunca trava nem derruba o fluxo principal: falha de rede ou configuração
incompleta é só reportada como False, nunca propagada como exceção.
"""

import requests

from config import (
    NOTIFY_WEBHOOK_FORMAT,
    NOTIFY_WEBHOOK_URL,
    SLACK_BOT_TOKEN,
    SLACK_CHANNEL_ID,
)

_TIMEOUT_SECONDS = 10
_SLACK_API_URL = "https://slack.com/api/chat.postMessage"


def _build_payload(title: str, message: str) -> dict:
    text = f"*{title}*\n{message}"
    if NOTIFY_WEBHOOK_FORMAT == "slack":
        return {"text": text}
    if NOTIFY_WEBHOOK_FORMAT == "discord":
        return {"content": text}
    return {"title": title, "message": message}


def _send_via_slack_api(title: str, message: str) -> bool:
    try:
        resp = requests.post(
            _SLACK_API_URL,
            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
            json={"channel": SLACK_CHANNEL_ID, "text": f"*{title}*\n{message}"},
            timeout=_TIMEOUT_SECONDS,
        )
        data = resp.json()
        return resp.status_code < 300 and data.get("ok", False)
    except requests.RequestException:
        return False


def _send_via_webhook(title: str, message: str) -> bool:
    try:
        resp = requests.post(
            NOTIFY_WEBHOOK_URL, json=_build_payload(title, message), timeout=_TIMEOUT_SECONDS
        )
        return resp.status_code < 300
    except requests.RequestException:
        return False


def _send_via_telegram(title: str, message: str) -> bool:
    """Envia pelo Telegram (Fase 8), se configurado. Import lazy para não
    criar dependência de carga entre os módulos e manter o telegram opcional."""
    try:
        from tools import telegram

        if telegram.is_configured():
            return telegram.send_telegram(f"*{title}*\n{message}")
    except Exception:
        return False
    return False


def send_notification(title: str, message: str) -> bool:
    """Envia uma notificação por TODOS os canais configurados (Slack API,
    webhook genérico, Telegram). Retorna True se ALGUM canal enviou com
    sucesso, False se nada está configurado ou todos falharam. Tenta todos
    (não para no primeiro sucesso) para que uma notificação importante chegue
    em cada destino que o operador configurou."""
    sent = False
    if SLACK_BOT_TOKEN and SLACK_CHANNEL_ID:
        sent = _send_via_slack_api(title, message) or sent
    if NOTIFY_WEBHOOK_URL:
        sent = _send_via_webhook(title, message) or sent
    sent = _send_via_telegram(title, message) or sent
    return sent


def is_configured() -> bool:
    if SLACK_BOT_TOKEN and SLACK_CHANNEL_ID:
        return True
    if NOTIFY_WEBHOOK_URL:
        return True
    try:
        from tools import telegram

        return telegram.is_configured()
    except Exception:
        return False
