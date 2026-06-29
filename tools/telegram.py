"""Notificação e controle via Telegram Bot API (Fase 8).

Dois sentidos:

  - SAÍDA (sempre): a Nexus envia mensagens ao chat/grupo configurado —
    notificações de bloqueio de inadimplente, queda de equipamento, etc.
    Ligado ao tools/notify.py como canal adicional.

  - ENTRADA (bidirecional, opt-in): o operador comanda o NOC pelo grupo do
    Telegram (ex.: "/status", "/block c1", "/devices"). O endpoint
    api.server:/telegram/webhook recebe os updates do Telegram, valida a
    origem (secret token + chat_id autorizado) e roteia o texto ao agente —
    análogo ao slash command do Slack. Ações de alto risco continuam passando
    pelo gate de tools/risk.py, qualquer que seja o canal.

Segurança da entrada (defesa em profundidade):
  1. secret token do webhook (X-Telegram-Bot-Api-Secret-Token) — prova que o
     update veio do Telegram com o segredo que só nós e ele conhecemos.
  2. chat_id autorizado — só comandos vindos do TELEGRAM_CHAT_ID são acatados;
     qualquer outro chat é ignorado e registrado.

Nunca trava nem derruba o fluxo: token ausente ou falha de rede vira False,
nunca exceção — mesmo contrato de tools/notify._send_via_webhook.
"""

import secrets

import requests

from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_WEBHOOK_SECRET

_TIMEOUT_SECONDS = 10
# Limite de tamanho de mensagem do Telegram é 4096; deixamos folga.
_MAX_MESSAGE = 4000


def is_configured() -> bool:
    return bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)


# ---------- saída ----------

def _post_message(chat_id, text: str) -> bool:
    if not TELEGRAM_BOT_TOKEN:
        return False
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        resp = requests.post(
            url,
            json={"chat_id": chat_id, "text": text[:_MAX_MESSAGE], "parse_mode": "Markdown"},
            timeout=_TIMEOUT_SECONDS,
        )
        data = resp.json()
        return resp.status_code < 300 and bool(data.get("ok", False))
    except (requests.RequestException, ValueError):
        return False


def send_telegram(text: str) -> bool:
    """Envia ao chat/grupo configurado (TELEGRAM_CHAT_ID). Retorna True só se o
    Telegram confirmou (ok=true)."""
    if not is_configured():
        return False
    return _post_message(TELEGRAM_CHAT_ID, text)


def send_telegram_to(chat_id, text: str) -> bool:
    """Envia a um chat específico — usado pela resposta do webhook ao remetente
    (que já foi validado como o chat autorizado)."""
    return _post_message(chat_id, text)


# ---------- entrada (webhook bidirecional) ----------

def webhook_configured() -> bool:
    """True só se o controle bidirecional está totalmente configurado (bot +
    chat + secret). Sem qualquer um, o endpoint recusa em vez de operar."""
    return bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID and TELEGRAM_WEBHOOK_SECRET)


def webhook_secret_ok(header_value: str | None) -> bool:
    """Compara (timing-safe) o header X-Telegram-Bot-Api-Secret-Token com o
    segredo configurado. False se não há segredo configurado."""
    if not TELEGRAM_WEBHOOK_SECRET:
        return False
    return secrets.compare_digest(header_value or "", TELEGRAM_WEBHOOK_SECRET)


def is_authorized_chat(chat_id) -> bool:
    """Só o chat/grupo configurado pode comandar o NOC."""
    return bool(TELEGRAM_CHAT_ID) and str(chat_id) == str(TELEGRAM_CHAT_ID)


def parse_update(update: dict) -> dict | None:
    """Extrai {chat_id, text, from_id} de um Update do Telegram, ou None se não
    for uma mensagem de texto (ex.: foto, evento de entrada/saída de membro).
    Função pura — testável sem rede."""
    if not isinstance(update, dict):
        return None
    msg = update.get("message") or update.get("edited_message")
    if not isinstance(msg, dict):
        return None
    text = (msg.get("text") or "").strip()
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    if not text or chat_id is None:
        return None
    frm = msg.get("from") or {}
    return {"chat_id": chat_id, "text": text, "from_id": frm.get("id")}


def set_webhook(public_url: str) -> str:
    """Registra o webhook no Telegram (setWebhook) apontando para public_url,
    já com o secret token configurado. public_url deve ser HTTPS e terminar em
    /telegram/webhook (ex.: https://noc.xfiber.com.br/telegram/webhook).
    Conveniência para o operador não precisar montar o curl à mão."""
    if not TELEGRAM_BOT_TOKEN:
        return "Telegram não configurado (TELEGRAM_BOT_TOKEN vazio)."
    if not TELEGRAM_WEBHOOK_SECRET:
        return "TELEGRAM_WEBHOOK_SECRET vazio — defina-o antes de registrar o webhook."
    if not public_url.startswith("https://"):
        return "O Telegram exige HTTPS no webhook. public_url precisa começar com https://."
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/setWebhook"
    try:
        resp = requests.post(
            url,
            json={"url": public_url, "secret_token": TELEGRAM_WEBHOOK_SECRET},
            timeout=_TIMEOUT_SECONDS,
        )
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        return f"Falha ao registrar webhook: {exc}"
    if data.get("ok"):
        return f"Webhook registrado com sucesso em {public_url}."
    return f"Telegram recusou o registro: {data.get('description', data)}"


def normalize_command(text: str) -> str:
    """Normaliza um comando de Telegram para texto natural ao agente: remove a
    barra inicial e um eventual @nomedobot do primeiro token. Ex.:
    '/status@NexusBot agora' -> 'status agora'."""
    text = text.strip()
    if not text:
        return text
    parts = text.split(maxsplit=1)
    head = parts[0]
    if head.startswith("/"):
        head = head[1:]
    head = head.split("@", 1)[0]  # tira @botname de comandos em grupo
    rest = parts[1] if len(parts) > 1 else ""
    return (head + (" " + rest if rest else "")).strip()
