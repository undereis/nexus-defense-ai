"""Gate de confirmação humana para ações de alto risco.

Substitui o modelo anterior de "tudo ou nada por toggle": mesmo com
ALLOW_ACTIVE_EXPLOITATION=true no .env, ações de alto risco (exploração
ativa, brute force, SQLi automatizado, escrita real no Mikrotik) não
executam na hora — ficam pendentes até o criador confirmar
explicitamente, informando um código que NUNCA é devolvido ao contexto
do agente.

Barreira técnica real (não só instrução de prompt): o código de
confirmação é gerado aqui, enviado por um canal fora da conversa
(webhook/Slack configurado, ou stdout do terminal local) e nunca incluído
na string retornada pela tool — ou seja, nunca entra no contexto do LLM
pelo caminho da própria criação da ação. Para confirmar, o criador
precisa ter visto o código nesse canal externo e repassá-lo numa
mensagem nova; só então o agente tem o código para chamar
confirm_and_execute. Isso fecha a brecha de "o próprio agente cria e
confirma no mesmo turno", que existia quando o id sozinho bastava.
"""

import json
import secrets

from database.db import (
    create_pending_action,
    get_pending_action,
    list_pending_actions,
    log_event,
    resolve_pending_action,
    search_knowledge,
)

# Funções reais por trás de cada ação de alto risco. Registradas aqui
# (não nas tools do agente) para que confirm_pending_action consiga
# executar a ação original sem o agente precisar repassar argumentos.
_ACTIONS: dict[str, callable] = {}


def register_action(name: str, func: callable) -> None:
    _ACTIONS[name] = func


def _quick_kb_reference(query: str) -> str:
    """Busca o melhor resultado da base de conhecimento local para dar
    contexto técnico automático à confirmação, sem depender do LLM lembrar
    de chamar search_knowledge_base por conta própria."""
    try:
        rows = search_knowledge(query, limit=1)
    except Exception:
        return ""
    if not rows:
        return ""
    _doc_id, topic, title, source_url, snippet = rows[0]
    return f"\nReferência técnica encontrada ([{topic}] {title}, fonte: {source_url}):\n  {snippet}"


def _deliver_code_out_of_band(action_id: int, summary: str, code: str) -> None:
    """Manda o código de confirmação por um canal que não passa pelo
    contexto do agente: webhook/Slack se configurado, e sempre também no
    stdout do processo (visível no terminal onde o criador roda a Nexus,
    mas não no texto que volta para o LLM)."""
    message = f"Ação pendente [{action_id}]: {summary}\nCódigo de confirmação: {code}"
    print(f"\n>>> NEXUS — CONFIRMAÇÃO NECESSÁRIA >>>\n{message}\n<<<\n")
    try:
        from tools import notify

        if notify.is_configured():
            notify.send_notification("Nexus: confirmação de ação de alto risco", message)
    except Exception:
        pass  # entrega no terminal já aconteceu; webhook é bônus, não bloqueante


def request_confirmation(
    tool_name: str, summary: str, ttl_minutes: int = 10, kb_query: str = "", **kwargs
) -> str:
    """Cria uma ação pendente em vez de executar na hora. Retorna o texto
    que a tool deve devolver ao agente — SEM o código de confirmação, que
    vai só por canal externo (terminal/webhook). Se kb_query for
    informado, anexa a melhor referência da base de conhecimento local."""
    code = secrets.token_hex(3)  # 6 caracteres hex, curto o bastante para digitar
    action_id = create_pending_action(tool_name, json.dumps(kwargs), summary, code, ttl_minutes)
    log_event(
        "pending_action_created",
        None,
        f"id={action_id} tool={tool_name} summary={summary!r}",
        action_taken="aguardando confirmação",
    )
    _deliver_code_out_of_band(action_id, summary, code)
    kb_note = _quick_kb_reference(kb_query) if kb_query else ""
    return (
        f"AÇÃO DE ALTO RISCO NÃO EXECUTADA — pendente de confirmação (id={action_id}).\n"
        f"Resumo: {summary}"
        f"{kb_note}\n"
        f"Expira em {ttl_minutes} minutos. Um código de confirmação foi enviado "
        f"fora desta conversa (terminal/webhook). Para executar, o criador precisa "
        f"olhar esse código e informá-lo numa mensagem nova — você não tem acesso a "
        f"ele por nenhum outro meio."
    )


def confirm_and_execute(action_id: int, code: str) -> str:
    """Executa uma ação pendente, se o código informado bater com o que
    foi enviado fora desta conversa. NUNCA invente ou adivinhe um código —
    se o criador não informou um explicitamente na mensagem mais recente
    dele, pergunte a ele em vez de chamar esta tool."""
    row = get_pending_action(action_id)
    if row is None:
        return f"Ação pendente {action_id} não encontrada."

    _id, tool_name, args_json, summary, real_code, status, _created_at, _resolved_at, expires_at = row

    if status != "pending":
        return f"Ação {action_id} já está com status '{status}', não pode ser executada de novo."

    if not code or code.strip().lower() != real_code.lower():
        log_event(
            "pending_action_code_mismatch", None,
            f"id={action_id} tool={tool_name}", action_taken="código incorreto, execução bloqueada",
        )
        return (
            f"Código de confirmação incorreto para a ação {action_id}. A ação continua "
            "pendente — não foi executada."
        )

    from database.db import get_conn

    with get_conn() as conn:
        still_valid = conn.execute(
            "SELECT 1 FROM pending_actions WHERE id = ? AND expires_at > datetime('now')",
            (action_id,),
        ).fetchone()
    if not still_valid:
        resolve_pending_action(action_id, "expirada")
        log_event("pending_action_expired", None, f"id={action_id} tool={tool_name}", action_taken="expirou")
        return f"Ação {action_id} expirou antes de ser confirmada. Peça para refazer a solicitação."

    func = _ACTIONS.get(tool_name)
    if func is None:
        return f"Erro interno: nenhuma implementação registrada para '{tool_name}'."

    kwargs = json.loads(args_json)
    log_event("pending_action_confirmed", None, f"id={action_id} tool={tool_name}", action_taken="confirmado pelo criador")
    result = func(**kwargs)
    resolve_pending_action(action_id, "executada")
    log_event("pending_action_executed", None, f"id={action_id} tool={tool_name}", action_taken="executado")
    return f"[Ação {action_id} confirmada e executada]\n{result}"


def cancel(action_id: int) -> str:
    row = get_pending_action(action_id)
    if row is None:
        return f"Ação pendente {action_id} não encontrada."
    if row[5] != "pending":
        return f"Ação {action_id} já está com status '{row[5]}'."
    resolve_pending_action(action_id, "cancelada")
    log_event("pending_action_cancelled", None, f"id={action_id}", action_taken="cancelado pelo criador")
    return f"Ação {action_id} cancelada."


def sweep_expired() -> list[int]:
    """Marca como 'expirada' toda ação pendente cujo prazo já passou, e
    notifica fora de banda (mesmo canal usado para o código). Sem isso,
    uma ação esquecida fica com status 'pending' indefinidamente — só era
    detectada como expirada se alguém tentasse confirmá-la depois do
    prazo. Retorna a lista de ids expirados nesta varredura."""
    from database.db import get_conn

    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, tool_name, summary FROM pending_actions
            WHERE status = 'pending' AND expires_at <= datetime('now')
            """
        ).fetchall()

    expired_ids = []
    for action_id, tool_name, summary in rows:
        resolve_pending_action(action_id, "expirada")
        log_event(
            "pending_action_expired", None, f"id={action_id} tool={tool_name}",
            action_taken="expirou sem confirmação",
        )
        try:
            from tools import notify

            if notify.is_configured():
                notify.send_notification(
                    "Nexus: ação pendente expirou",
                    f"A ação [{action_id}] '{summary}' expirou sem confirmação e NÃO foi executada.",
                )
        except Exception:
            pass
        expired_ids.append(action_id)
    return expired_ids


def list_pending() -> str:
    rows = list_pending_actions()
    if not rows:
        return "Nenhuma ação de alto risco pendente de confirmação."
    lines = ["Ações pendentes de confirmação:"]
    for action_id, tool_name, summary, created_at, expires_at in rows:
        lines.append(f"  [{action_id}] {tool_name} — {summary} (criada {created_at}, expira {expires_at})")
    return "\n".join(lines)
