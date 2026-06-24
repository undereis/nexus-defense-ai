"""Nexus Defense AI — backend HTTP.

Primeiro passo de "CLI single-user" para "serviço": expõe o agente via
HTTP autenticado, sem remover o CLI (main.py continua funcionando do
mesmo jeito, usando o mesmo runtime compartilhado em agents/runtime.py).

Rodar: ./venv/bin/uvicorn api.server:app --host 127.0.0.1 --port 8000
"""

import secrets

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from agents.runtime import ask_agent
from config import API_TOKEN
from database.db import init_db

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
