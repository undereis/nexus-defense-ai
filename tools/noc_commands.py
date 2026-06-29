"""Fast-path de comandos do NOC (Fase 8).

O webhook do Telegram roteia todo texto ao agente (LLM) por padrão — ótimo para
linguagem natural e ações que pedem julgamento, mas caro e lento (segundos) para
as CONSULTAS operacionais frequentes ("/status", "/devices"...). Este módulo é
um roteador determinístico que responde essas consultas direto, em
milissegundos, sem LLM.

Contrato: handle_command(text) devolve a resposta (str) se reconheceu um comando
de consulta, ou None se não — e nesse caso o chamador cai no agente. Por
segurança, SÓ comandos de leitura entram no fast-path; ações de risco
(bloquear/desbloquear assinante) continuam indo pelo agente, que tem mais
contexto e guarda. Read-only aqui.
"""

from config import SUBSCRIBER_BLOCK_DAYS
from database.db import (
    list_device_outages,
    list_monitored_devices,
    list_subscribers,
)
from tools import billing, noc_report

_HELP = (
    "*Nexus NOC — comandos rápidos:*\n"
    "/status — painel consolidado (assinantes, equipamentos, quedas)\n"
    "/devices — equipamentos monitorados e estado\n"
    "/outages — chamados de queda abertos\n"
    "/subscribers — assinantes e situação\n"
    "/delinquent — inadimplentes que seriam bloqueados\n"
    "/help — esta ajuda\n"
    "\nPara ações (bloquear/desbloquear assinante) ou perguntas livres, é só "
    "escrever em linguagem natural — eu te respondo."
)

# Sinônimos PT/EN -> ação canônica. Tudo já chega sem a barra e sem @bot
# (telegram.normalize_command roda antes), mas toleramos a barra mesmo assim.
_READ_COMMANDS = {
    "help": "help", "ajuda": "help", "start": "help", "comandos": "help",
    "status": "status", "noc": "status", "painel": "status",
    "devices": "devices", "equipamentos": "devices", "dispositivos": "devices",
    "outages": "outages", "quedas": "outages", "chamados": "outages",
    "subscribers": "subscribers", "assinantes": "subscribers", "clientes": "subscribers",
    "delinquent": "delinquent", "inadimplentes": "delinquent",
}


def _format_devices() -> str:
    rows = list_monitored_devices()
    if not rows:
        return "Nenhum equipamento cadastrado para monitoramento."
    lines = ["*Equipamentos monitorados:*"]
    icon = {"online": "🟢", "offline": "🔴", "unknown": "⚪"}
    for did, name, ip, _model, location, dtype, enabled, status, _last in rows:
        en = "" if enabled else " (desabilitado)"
        loc = f" — {location}" if location else ""
        lines.append(f"{icon.get(status, '⚪')} {name or did} `{ip}` ({dtype}){en}{loc}")
    return "\n".join(lines)


def _format_outages() -> str:
    rows = list_device_outages("aberto", limit=50)
    if not rows:
        return "Nenhum chamado de queda aberto. ✅"
    lines = [f"*Chamados de queda abertos ({len(rows)}):*"]
    for did, ip, name, reason, _st, opened_at, _res in rows:
        lines.append(f"🔴 {name or did} `{ip}` — {reason} — desde {opened_at}")
    return "\n".join(lines)


def _format_subscribers() -> str:
    rows = list_subscribers()
    if not rows:
        return "Nenhum assinante cadastrado."
    total = len(rows)
    blocked = sum(1 for r in rows if r[5] == "bloqueado_inadimplencia")
    pend = sum(1 for r in rows if r[6] == "pendente")
    lines = [f"*Assinantes: {total}* (bloqueados {blocked}, fatura pendente {pend})"]
    for sid, name, ip, _host, _iface, st, inv, days in rows[:20]:
        flag = "🔴" if st == "bloqueado_inadimplencia" else "🟢"
        lines.append(f"{flag} [{sid}] {name or '—'} `{ip}` — {inv} ({days}d)")
    if total > 20:
        lines.append(f"… e mais {total - 20}.")
    return "\n".join(lines)


def _format_delinquent() -> str:
    try:
        delinquent = billing.get_billing_source().list_delinquent(SUBSCRIBER_BLOCK_DAYS)
    except Exception as exc:
        return f"Não foi possível consultar a fonte de cobrança: {exc}"
    if not delinquent:
        return f"Nenhum inadimplente com atraso >= {SUBSCRIBER_BLOCK_DAYS} dias."
    lines = [f"*Inadimplentes (atraso >= {SUBSCRIBER_BLOCK_DAYS}d):*"]
    for s in delinquent:
        lines.append(f"• [{s['subscriber_id']}] `{s['ip_address']}` — {s.get('days_overdue', '?')}d")
    return "\n".join(lines)


def handle_command(text: str) -> str | None:
    """Responde um comando de CONSULTA do NOC sem LLM, ou None se o texto não
    for um comando reconhecido (caller cai no agente)."""
    if not text or not text.strip():
        return None
    first = text.strip().split()[0].lower().lstrip("/")
    action = _READ_COMMANDS.get(first)
    if action is None:
        return None
    if action == "help":
        return _HELP
    if action == "status":
        return noc_report.noc_status_report()
    if action == "devices":
        return _format_devices()
    if action == "outages":
        return _format_outages()
    if action == "subscribers":
        return _format_subscribers()
    if action == "delinquent":
        return _format_delinquent()
    return None
