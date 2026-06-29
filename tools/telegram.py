"""Notificação via Telegram Bot API.

Canal de notificação ADICIONAL, no mesmo espírito de tools/notify.py: leva
os avisos da Nexus para fora do terminal. Pensado para o caso de uso de
operação de ISP (Fase 8) — bloqueio de inadimplentes e queda de
equipamentos chegando num grupo de Telegram da equipe — mas serve para
qualquer notificação.

Só SAÍDA (outbound) nesta fase: a Nexus envia mensagens; não recebe
comandos por aqui (controle bidirecional via Telegram, se um dia existir,
seria gated como o slash command do Slack já é).

Nunca trava nem derruba o fluxo principal: token ausente ou falha de rede
é só reportada como False, nunca propagada como exceção — mesmo contrato
de tools/notify._send_via_webhook.
"""

import requests

from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

_TIMEOUT_SECONDS = 10


def is_configured() -> bool:
    return bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)


def send_telegram(text: str) -> bool:
    """Envia uma mensagem ao chat/grupo configurado. Retorna True só se o
    Telegram confirmou o envio (ok=true), False se não está configurado ou
    se houve qualquer falha."""
    if not is_configured():
        return False
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        resp = requests.post(
            url,
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "Markdown"},
            timeout=_TIMEOUT_SECONDS,
        )
        data = resp.json()
        return resp.status_code < 300 and bool(data.get("ok", False))
    except (requests.RequestException, ValueError):
        # ValueError cobre resp.json() em corpo não-JSON.
        return False
