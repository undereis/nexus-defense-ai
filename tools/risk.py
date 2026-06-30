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
    increment_failed_attempts,
    list_pending_actions,
    log_event,
    resolve_pending_action,
    search_knowledge,
)

MAX_FAILED_ATTEMPTS = 5

# Funções reais por trás de cada ação de alto risco. Registradas aqui
# (não nas tools do agente) para que confirm_pending_action consiga
# executar a ação original sem o agente precisar repassar argumentos.
_ACTIONS: dict[str, callable] = {}


def register_action(name: str, func: callable) -> None:
    _ACTIONS[name] = func


# Mapa do tool_name (registrado no gate) → action_type da policy engine do
# Control Plane. Todas as tools de alto risco funilam por request_confirmation,
# então este é o ponto único para roteá-las pela governança (RBAC + trava de
# segurança + modo operacional) ANTES do gate de aprovação. As tools já checam
# os próprios toggles, então o overlay NÃO reavalia toggle (evita divergência).
_TOOL_ACTION_MAP: dict[str, str] = {
    "run_exploit_module": "run_exploit",
    "brute_force_login": "brute_force",
    "run_sqlmap_scan": "run_sqlmap",
    "mikrotik_add_firewall_rule": "mikrotik_write",
    "mikrotik_remove_firewall_rule": "mikrotik_write",
    "mikrotik_create_pppoe_user": "mikrotik_write",
    "mikrotik_remove_pppoe_user": "mikrotik_write",
    "mikrotik_run_command": "mikrotik_write",
    "bgp_flowspec_announce": "bgp_flowspec",
    "bgp_flowspec_withdraw": "bgp_flowspec",
    "asn_block_execute": "asn_block",
    "brbos_block_domain": "brbos_block_domain",
}

_TARGET_KEYS = ("ip", "target", "host", "src_address", "dst_address", "cidr",
                "domain", "url", "asn", "username", "rule_id")


def _extract_target(kwargs: dict) -> str:
    for key in _TARGET_KEYS:
        val = kwargs.get(key)
        if val:
            return str(val)
    return ""


def _governance_precheck(tool_name: str, kwargs: dict) -> str | None:
    """Roteia a ação pela governança do Control Plane. Retorna uma mensagem se a
    ação for NEGADA/dry-run (e NÃO deve criar pendência), ou None para seguir ao
    gate. Só atua em tool_names mapeados; nunca levanta (fail-open: na dúvida,
    segue para o gate de aprovação, que continua exigindo confirmação)."""
    action_type = _TOOL_ACTION_MAP.get(tool_name)
    if action_type is None:
        return None
    try:
        from core import control_plane as cp
        from core.models import Decision

        req = cp.make_request(action_type, target=_extract_target(kwargs), params=dict(kwargs))
        dec = cp.precheck_runtime(req)
    except Exception:
        return None
    if dec.decision is Decision.DENY:
        return f"AÇÃO NEGADA pela governança (Control Plane): {dec.reason}"
    if dec.decision is Decision.DRY_RUN_ONLY:
        return f"[modo {dec.mode}] ação '{action_type}' NÃO executada (dry-run): {dec.reason}"
    return None


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


def _notify_out_of_band(title: str, message: str) -> None:
    try:
        from tools import notify

        if notify.is_configured():
            notify.send_notification(title, message)
    except Exception:
        pass


def _deliver_code_out_of_band(action_id: int, summary: str, code: str) -> None:
    """Manda o código de confirmação por um canal que não passa pelo
    contexto do agente: webhook/Slack se configurado, e sempre também no
    stdout do processo (visível no terminal onde o criador roda a Nexus,
    mas não no texto que volta para o LLM)."""
    message = f"Ação pendente [{action_id}]: {summary}\nCódigo de confirmação: {code}"
    print(f"\n>>> NEXUS — CONFIRMAÇÃO NECESSÁRIA >>>\n{message}\n<<<\n")
    _notify_out_of_band("Nexus: confirmação de ação de alto risco", message)


def request_confirmation(
    tool_name: str, summary: str, ttl_minutes: int = 10, kb_query: str = "",
    _skip_policy: bool = False, **kwargs
) -> str:
    """Cria uma ação pendente em vez de executar na hora. Retorna o texto
    que a tool deve devolver ao agente — SEM o código de confirmação, que
    vai só por canal externo (terminal/webhook). Se kb_query for
    informado, anexa a melhor referência da base de conhecimento local.

    Antes de criar a pendência, roteia a ação pela governança do Control Plane
    (RBAC + trava de segurança + modo operacional): em modo lab/replay ou alvo
    proibido/papel sem permissão, NÃO cria pendência — devolve o motivo.
    `_skip_policy=True` pula isso (usado pelo próprio Control Plane, que já avaliou)."""
    if not _skip_policy:
        blocked = _governance_precheck(tool_name, kwargs)
        if blocked is not None:
            return blocked

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

    (_id, tool_name, args_json, summary, real_code, status,
     _created_at, _resolved_at, expires_at, failed_attempts) = row

    if status != "pending":
        return f"Ação {action_id} já está com status '{status}', não pode ser executada de novo."

    # Comparação timing-safe: comparar com `!=` direto vaga informação de
    # timing proporcional a quantos caracteres iniciais batem, reduzindo
    # o espaço de busca de um ataque por força bruta dentro do TTL.
    if not code or not secrets.compare_digest(code.strip().lower(), real_code.lower()):
        new_count = increment_failed_attempts(action_id)
        log_event(
            "pending_action_code_mismatch", None,
            f"id={action_id} tool={tool_name} attempt={new_count}", action_taken="código incorreto, execução bloqueada",
        )
        # Rate-limit: sem isso, um código de 6 hex (16M combinações) é
        # adivinhável por força bruta automatizada dentro da janela de TTL.
        # Depois de poucas tentativas erradas, a ação inteira é cancelada —
        # o criador precisa pedir a ação de novo, recebendo um código novo.
        if new_count >= MAX_FAILED_ATTEMPTS:
            resolve_pending_action(action_id, "bloqueada_por_tentativas")
            log_event(
                "pending_action_locked", None,
                f"id={action_id} tool={tool_name} attempts={new_count}",
                action_taken="cancelada por excesso de tentativas incorretas",
            )
            _notify_out_of_band(
                "Nexus: ação bloqueada por tentativas incorretas",
                f"A ação [{action_id}] '{summary}' foi cancelada após {new_count} tentativas "
                "de código incorretas seguidas. Se isso não foi você, alguém tentou adivinhar "
                "o código — investigue.",
            )
            return (
                f"Ação {action_id} CANCELADA: excesso de tentativas de código incorreto "
                f"({new_count}). Por segurança, peça a ação de novo para receber um código novo."
            )
        return (
            f"Código de confirmação incorreto para a ação {action_id} "
            f"(tentativa {new_count}/{MAX_FAILED_ATTEMPTS}). A ação continua pendente — "
            "não foi executada."
        )

    from database.db import get_conn

    # Reivindicação atômica: só uma chamada concorrente consegue mover o
    # status de 'pending' para 'em_execucao' (UPDATE...WHERE condicional).
    # Isso fecha a race condition de duas confirmações simultâneas com o
    # mesmo código executarem a ação duas vezes — sem isso, ambas passavam
    # da checagem de código (feita acima, antes de qualquer lock) e a
    # segunda sobrescrevia o resultado da primeira.
    with get_conn() as conn:
        claim = conn.execute(
            "UPDATE pending_actions SET status = 'em_execucao' "
            "WHERE id = ? AND status = 'pending' AND expires_at > datetime('now')",
            (action_id,),
        )
        claimed = claim.rowcount == 1

    if not claimed:
        # Não conseguimos reivindicar: ou expirou, ou outra chamada já
        # está executando/executou. Distingue os dois casos para a
        # mensagem ficar honesta sobre o que de fato aconteceu.
        current = get_pending_action(action_id)
        current_status = current[5] if current else "desconhecido"
        if current_status == "pending":
            # Só pode ter sido expiração detectada entre a leitura e a
            # tentativa de claim (corrida rara, mas possível).
            resolve_pending_action(action_id, "expirada")
            log_event("pending_action_expired", None, f"id={action_id} tool={tool_name}", action_taken="expirou")
            return f"Ação {action_id} expirou antes de ser confirmada. Peça para refazer a solicitação."
        return (
            f"Ação {action_id} já estava sendo executada ou foi resolvida por outra confirmação "
            f"simultânea (status atual: '{current_status}'). Não executada de novo."
        )

    func = _ACTIONS.get(tool_name)
    if func is None:
        resolve_pending_action(action_id, "erro_interno")
        return f"Erro interno: nenhuma implementação registrada para '{tool_name}'."

    kwargs = json.loads(args_json)
    log_event("pending_action_confirmed", None, f"id={action_id} tool={tool_name}", action_taken="confirmado pelo criador")
    try:
        result = func(**kwargs)
    except Exception as exc:
        # Se a execução falhar, o status NUNCA deve ficar 'executada' —
        # isso criava um descompasso entre a auditoria (que diria
        # "executado") e a realidade (a ação nunca rodou de fato).
        resolve_pending_action(action_id, "falhou")
        log_event(
            "pending_action_failed", None, f"id={action_id} tool={tool_name} error={exc!r}",
            action_taken="falhou na execução",
        )
        return f"Ação {action_id} confirmada, mas a execução falhou: {exc}"

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
        _notify_out_of_band(
            "Nexus: ação pendente expirou",
            f"A ação [{action_id}] '{summary}' expirou sem confirmação e NÃO foi executada.",
        )
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
