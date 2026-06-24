"""Notificações fora do terminal.

Tudo que a Nexus decide e age sozinha (auto-isolamento, drift de
firewall, mudança em auditoria proativa) até aqui só chegava a você se
o terminal estivesse aberto na sua frente. Isso envia o mesmo aviso
para um webhook externo (Slack, Discord, ou qualquer endpoint custom),
para você saber mesmo longe da máquina.

Nunca trava nem derruba o fluxo principal: falha de rede ou webhook mal
configurado é só logada, nunca propagada como exceção.
"""

import requests

from config import NOTIFY_WEBHOOK_FORMAT, NOTIFY_WEBHOOK_URL

_TIMEOUT_SECONDS = 10


def _build_payload(title: str, message: str) -> dict:
    text = f"*{title}*\n{message}"
    if NOTIFY_WEBHOOK_FORMAT == "slack":
        return {"text": text}
    if NOTIFY_WEBHOOK_FORMAT == "discord":
        return {"content": text}
    return {"title": title, "message": message}


def send_notification(title: str, message: str) -> bool:
    """Envia uma notificação ao webhook configurado. Retorna True se enviou
    com sucesso, False se não está configurado ou falhou (nunca lança)."""
    if not NOTIFY_WEBHOOK_URL:
        return False
    try:
        resp = requests.post(
            NOTIFY_WEBHOOK_URL, json=_build_payload(title, message), timeout=_TIMEOUT_SECONDS
        )
        return resp.status_code < 300
    except requests.RequestException:
        return False


def is_configured() -> bool:
    return bool(NOTIFY_WEBHOOK_URL)
