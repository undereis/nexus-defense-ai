"""Gate de confirmação humana para ações de alto risco.

Substitui o modelo anterior de "tudo ou nada por toggle": mesmo com
ALLOW_ACTIVE_EXPLOITATION=true no .env, ações de alto risco (exploração
ativa, brute force, SQLi automatizado, escrita real no Mikrotik) não
executam na hora — ficam pendentes até o criador confirmar
explicitamente em uma mensagem nova, depois de ver o resumo da ação.

Isso não é uma barreira criptográfica (o agente que cria a ação pendente
é o mesmo processo que pode executá-la depois), é uma barreira de
processo: a confirmação exige uma nova mensagem do criador no chat,
e cada execução fica registrada na trilha de auditoria com o id da
ação pendente correspondente. O docstring de confirm_pending_action
instrui explicitamente o agente a nunca se autoconfirmar.
"""

import json

from database.db import (
    create_pending_action,
    get_pending_action,
    list_pending_actions,
    log_event,
    resolve_pending_action,
)

# Funções reais por trás de cada ação de alto risco. Registradas aqui
# (não nas tools do agente) para que confirm_pending_action consiga
# executar a ação original sem o agente precisar repassar argumentos.
_ACTIONS: dict[str, callable] = {}


def register_action(name: str, func: callable) -> None:
    _ACTIONS[name] = func


def request_confirmation(tool_name: str, summary: str, ttl_minutes: int = 10, **kwargs) -> str:
    """Cria uma ação pendente em vez de executar na hora. Retorna o texto
    que a tool deve devolver ao agente (e, por extensão, ao criador)."""
    action_id = create_pending_action(tool_name, json.dumps(kwargs), summary, ttl_minutes)
    log_event(
        "pending_action_created",
        None,
        f"id={action_id} tool={tool_name} summary={summary!r}",
        action_taken="aguardando confirmação",
    )
    return (
        f"AÇÃO DE ALTO RISCO NÃO EXECUTADA — pendente de confirmação (id={action_id}).\n"
        f"Resumo: {summary}\n"
        f"Expira em {ttl_minutes} minutos. Para executar, o criador precisa dizer "
        f'explicitamente algo como "confirmo a ação {action_id}" em uma nova mensagem.'
    )


def confirm_and_execute(action_id: int) -> str:
    """Executa uma ação pendente, se ainda válida. NUNCA chame isto sem o
    criador ter pedido explicitamente a confirmação dessa ação específica
    na mensagem mais recente dele — não é uma decisão sua, agente."""
    row = get_pending_action(action_id)
    if row is None:
        return f"Ação pendente {action_id} não encontrada."

    _id, tool_name, args_json, summary, status, _created_at, _resolved_at, expires_at = row

    if status != "pending":
        return f"Ação {action_id} já está com status '{status}', não pode ser executada de novo."

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
    if row[4] != "pending":
        return f"Ação {action_id} já está com status '{row[4]}'."
    resolve_pending_action(action_id, "cancelada")
    log_event("pending_action_cancelled", None, f"id={action_id}", action_taken="cancelado pelo criador")
    return f"Ação {action_id} cancelada."


def list_pending() -> str:
    rows = list_pending_actions()
    if not rows:
        return "Nenhuma ação de alto risco pendente de confirmação."
    lines = ["Ações pendentes de confirmação:"]
    for action_id, tool_name, summary, created_at, expires_at in rows:
        lines.append(f"  [{action_id}] {tool_name} — {summary} (criada {created_at}, expira {expires_at})")
    return "\n".join(lines)
