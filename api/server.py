"""Nexus Defense AI — backend HTTP.

Primeiro passo de "CLI single-user" para "serviço": expõe o agente via
HTTP autenticado, sem remover o CLI (main.py continua funcionando do
mesmo jeito, usando o mesmo runtime compartilhado em agents/runtime.py).

Rodar: ./venv/bin/uvicorn api.server:app --host 127.0.0.1 --port 8000
"""

import secrets
from dataclasses import dataclass
from urllib.parse import parse_qs

import requests
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Security
from fastapi.responses import HTMLResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from agents.runtime import ask_agent
from config import API_TOKEN, NEXUS_ROLE_TOKENS, SLACK_SIGNING_SECRET
from core import rbac
from core import users as api_users
from database.db import init_db, log_event
from tools import dashboard, noc_api, noc_commands, telegram
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


def _role_token_map() -> dict[str, str]:
    """Parseia NEXUS_ROLE_TOKENS ('papel:token,papel:token') → {token: papel}."""
    out: dict[str, str] = {}
    for pair in (NEXUS_ROLE_TOKENS or "").split(","):
        pair = pair.strip()
        if ":" not in pair:
            continue
        role, tok = pair.split(":", 1)
        role, tok = role.strip(), tok.strip()
        if role and tok:
            out[tok] = role
    return out


_ROLE_TOKENS = _role_token_map()


@dataclass(frozen=True)
class Principal:
    """Quem está por trás do token: identidade (actor) + papel (RBAC)."""
    actor: str
    role: str


def _resolve_principal(token: str) -> Principal | None:
    """Resolve o token para um Principal, em ordem de precedência:
      1. token principal (NEXUS_API_TOKEN) → admin;
      2. NEXUS_ROLE_TOKENS do .env → papel mapeado;
      3. usuário real do banco (token hasheado) → seu papel.
    None se nenhum bater (token inválido)."""
    if token and secrets.compare_digest(token, _runtime_token):
        return Principal("api:main", "admin")
    for tok, role in _ROLE_TOKENS.items():
        if token and secrets.compare_digest(token, tok):
            return Principal(f"api:{role}", role)
    user = api_users.resolve_user(token)
    if user is not None:
        return Principal(f"user:{user['name']}", user["role"])
    return None


def _resolve_role(token: str) -> str | None:
    """Papel a partir do token (compat: o token principal é admin; NEXUS_ROLE_TOKENS
    e usuários reais mapeiam para seus papéis). None = inválido."""
    p = _resolve_principal(token)
    return p.role if p else None


def require_token(value: str = Security(_api_key_header)) -> Principal:
    """Valida o token e resolve o PRINCIPAL (identidade + papel). 401 se inválido.
    Endpoints de leitura usam só como dependência (qualquer papel válido lê);
    endpoints de ação capturam o Principal e passam papel/ator ao Control Plane."""
    token = value[len("Bearer "):] if value and value.startswith("Bearer ") else ""
    principal = _resolve_principal(token)
    if principal is None:
        raise HTTPException(status_code=401, detail="Token inválido ou ausente.")
    return principal


def require_permission(permission: str):
    """Fábrica de dependência: exige que o papel do token conceda `permission`
    (senão 403). Retorna o Principal. Para rotas de ação REST que não passam pelo
    caminho 200+deny do Control Plane (billing/devices)."""
    def _dep(principal: Principal = Depends(require_token)) -> Principal:
        if not rbac.has_permission(principal.role, permission):
            raise HTTPException(
                status_code=403,
                detail=f"papel '{principal.role}' não tem a permissão '{permission}'.",
            )
        return principal
    return _dep


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


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page():
    """Casca HTML do dashboard read-only (NOC + segurança). Os dados em si
    vêm de /dashboard/data, protegido por token; esta página só pede o token
    e renderiza."""
    return dashboard.dashboard_html()


@app.get("/dashboard/data", dependencies=[Depends(require_token)])
def dashboard_data():
    return dashboard.dashboard_data()


# ---------- API REST para clientes externos (GUI Delphi, etc) ----------
# Tudo sob /api/*, JSON, protegido pelo token (require_token). Contrato em
# docs/api.md. Consultas read-only; ações reaproveitam a guarda/auditoria dos
# módulos (tools/billing, tools/device_monitor).

@app.get("/api/overview", dependencies=[Depends(require_token)])
def api_overview():
    return dashboard.dashboard_data()


@app.get("/api/health", dependencies=[Depends(require_token)])
def api_health():
    return noc_api.health()


@app.get("/api/subscribers", dependencies=[Depends(require_token)])
def api_subscribers():
    return {"subscribers": noc_api.subscribers()}


@app.get("/api/devices", dependencies=[Depends(require_token)])
def api_devices():
    return {"devices": noc_api.devices()}


@app.get("/api/outages", dependencies=[Depends(require_token)])
def api_outages(status: str = "aberto"):
    return {"outages": noc_api.outages(status)}


@app.get("/api/events", dependencies=[Depends(require_token)])
def api_events(hours: float = 24):
    return {"events": noc_api.events(hours)}


@app.post("/api/subscribers/{subscriber_id}/block")
def api_block_subscriber(subscriber_id: str, reason: str = "bloqueio via API",
                         principal: Principal = Depends(require_token)):
    # O papel/ator resolvido do token vai ao Control Plane: um token readonly/
    # auditor não tem 'noc.block_subscriber' e a ação é NEGADA (200+deny,
    # governado + auditado com a identidade real).
    return noc_api.block_subscriber(subscriber_id, reason, actor=principal.actor, role=principal.role)


@app.post("/api/subscribers/{subscriber_id}/unblock")
def api_unblock_subscriber(subscriber_id: str, reason: str = "desbloqueio via API",
                           principal: Principal = Depends(require_token)):
    return noc_api.unblock_subscriber(subscriber_id, reason, actor=principal.actor, role=principal.role)


@app.post("/api/billing/run")
def api_run_billing(dry_run: bool = True,
                    principal: Principal = Depends(require_permission("noc.billing"))):
    return noc_api.run_billing(dry_run)


@app.post("/api/devices/check")
def api_check_devices(principal: Principal = Depends(require_permission("noc.device_check"))):
    return noc_api.check_devices()


class ModeRequest(BaseModel):
    mode: str


def _mode_payload() -> dict:
    from core import operating_mode
    return {
        "mode": operating_mode.get_operating_mode(),
        "allows_real_state_change": operating_mode.allows_real_state_change(),
        "valid_modes": list(operating_mode.VALID_MODES),
    }


@app.get("/api/mode", dependencies=[Depends(require_token)])
def api_get_mode():
    """MODO OPERACIONAL EFETIVO do backend (real|lab|replay) — a fonte da verdade da
    EXECUÇÃO. O cliente Tauri lê isto para refletir o modo REAL do motor, não só o
    modo visual local. Qualquer token válido pode ler."""
    return _mode_payload()


@app.post("/api/mode")
def api_set_mode(req: ModeRequest,
                 principal: Principal = Depends(require_permission("system.operating_mode"))):
    """Propõe trocar o modo operacional do backend. Só quem tem 'system.operating_mode'
    (admin) pode — os demais recebem 403 e a UI continua refletindo o modo efetivo
    atual. Modo inválido → 400. Auditado com a identidade real."""
    from core import operating_mode
    try:
        mode = operating_mode.set_operating_mode(req.mode)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    log_event("operating_mode_changed", None,
              f"mode={mode} actor={principal.actor}", action_taken="alterado via REST")
    return _mode_payload()


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
