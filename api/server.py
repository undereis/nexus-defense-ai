"""Nexus Defense AI — backend HTTP.

Primeiro passo de "CLI single-user" para "serviço": expõe o agente via
HTTP autenticado, sem remover o CLI (main.py continua funcionando do
mesmo jeito, usando o mesmo runtime compartilhado em agents/runtime.py).

Rodar: ./venv/bin/uvicorn api.server:app --host 127.0.0.1 --port 8000
"""

import secrets
from urllib.parse import parse_qs

import requests
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from agents.runtime import ask_agent
from config import API_TOKEN, SLACK_SIGNING_SECRET
from database.db import init_db, log_event
from tools import noc_commands, telegram
from tools.slack_verify import verify_signature

app = FastAPI(title="Nexus Defense AI", version="0.1.0")

_runtime_token = API_TOKEN
if not _runtime_token:
    _runtime_token = secrets.token_urlsafe(32)
    print(
        "\n[Nexus API] NEXUS_API_TOKEN não configurado no .env. Gerei um token "
        f"temporário válido só nesta execução:\n\n    {_runtime_token}\n\n"
        "Defina NEXUS_API_TOKEN no .env para um token fixo entre reinicializações.\n",
        flush=True,
    )

_api_key_header = APIKeyHeader(name="Authorization", auto_error=False)


def require_token(value: str = Security(_api_key_header)):
    expected = f"Bearer {_runtime_token}"
    if not value or not secrets.compare_digest(value, expected):
        raise HTTPException(status_code=401, detail="Token inválido ou ausente.")


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    reply: str


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/chat", response_model=ChatResponse, dependencies=[Depends(require_token)])
def chat(req: ChatRequest):
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Mensagem vazia.")
    reply = ask_agent(req.message)
    return ChatResponse(reply=reply)


def _answer_and_callback(text: str, response_url: str):
    try:
        reply = ask_agent(text)
    except Exception as exc:
        reply = f"Tive um erro processando isso: {exc}"
    try:
        requests.post(response_url, json={"response_type": "in_channel", "text": reply}, timeout=10)
    except requests.RequestException:
        pass  # melhor falhar silenciosamente aqui do que derrubar o background task


@app.post("/slack/command")
async def slack_command(request: Request, background_tasks: BackgroundTasks):
    """Slash command do Slack (ex: /nexus qual o status da rede?). Slack
    exige resposta em até 3s, então respondemos na hora e processamos a
    pergunta de verdade em segundo plano, entregando via response_url."""
    if not SLACK_SIGNING_SECRET:
        raise HTTPException(status_code=503, detail="SLACK_SIGNING_SECRET não configurado.")

    raw_body = (await request.body()).decode("utf-8")
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")

    if not verify_signature(SLACK_SIGNING_SECRET, timestamp, raw_body, signature):
        raise HTTPException(status_code=401, detail="Assinatura inválida.")

    fields = parse_qs(raw_body)
    text = (fields.get("text") or [""])[0]
    response_url = (fields.get("response_url") or [""])[0]

    if not text.strip():
        return {"response_type": "ephemeral", "text": "Manda uma pergunta ou comando depois do /nexus."}
    if not response_url:
        raise HTTPException(status_code=400, detail="response_url ausente.")

    background_tasks.add_task(_answer_and_callback, text, response_url)
    return {"response_type": "ephemeral", "text": f"🔄 Processando: \"{text}\"..."}


def _telegram_answer(text: str, chat_id):
    # Fast-path: consultas frequentes do NOC respondem direto, sem LLM
    # (milissegundos vs segundos). Só leitura; ações/linguagem natural caem
    # no agente, que tem mais contexto e guarda.
    reply = noc_commands.handle_command(text)
    if reply is None:
        try:
            reply = ask_agent(text)
        except Exception as exc:
            reply = f"Tive um erro processando isso: {exc}"
    telegram.send_telegram_to(chat_id, reply)


@app.post("/telegram/webhook")
async def telegram_webhook(request: Request, background_tasks: BackgroundTasks):
    """Webhook do Telegram para controle bidirecional do NOC (Fase 8). O
    Telegram faz POST aqui a cada mensagem no bot/grupo. Duas barreiras de
    segurança antes de processar: secret token (prova de origem) e chat_id
    autorizado. O texto vira comando ao agente, que responde pelo Telegram.
    Processa em background e devolve 200 na hora (o Telegram reenvia se não
    receber 2xx rápido)."""
    if not telegram.webhook_configured():
        raise HTTPException(
            status_code=503,
            detail="Webhook do Telegram não configurado (TELEGRAM_BOT_TOKEN + "
            "TELEGRAM_CHAT_ID + TELEGRAM_WEBHOOK_SECRET).",
        )
    if not telegram.webhook_secret_ok(request.headers.get("X-Telegram-Bot-Api-Secret-Token")):
        raise HTTPException(status_code=401, detail="Secret token inválido.")

    try:
        update = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Corpo não é JSON válido.")

    parsed = telegram.parse_update(update)
    if not parsed:
        return {"ok": True}  # update sem texto (foto/evento) — ignora sem erro

    if not telegram.is_authorized_chat(parsed["chat_id"]):
        log_event(
            "telegram_unauthorized", None,
            f"chat_id={parsed['chat_id']} from={parsed.get('from_id')}",
            action_taken="ignorado",
        )
        return {"ok": True}

    command = telegram.normalize_command(parsed["text"])
    background_tasks.add_task(_telegram_answer, command, parsed["chat_id"])
    return {"ok": True}
