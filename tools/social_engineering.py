"""Geração de conteúdo de engenharia social (pretexting/phishing simulado)
para engagements de red team formalmente autorizados.

ESCOPO DELIBERADAMENTE LIMITADO: este módulo só GERA TEXTO (templates de
e-mail, scripts de ligação/pretexting). Ele NUNCA envia e-mail, SMS, ou
faz qualquer contato com uma pessoa real — isso é categoricamente
diferente das outras ferramentas ofensivas da Nexus (que atacam máquinas),
porque aqui o "alvo" é uma pessoa. O contato real é sempre uma ação manual
e deliberada do criador, depois de revisar o conteúdo gerado.

Toda geração exige uma referência de autorização (ex: número do contrato/
SOW do engagement) e é registrada na trilha de auditoria — não verifica se
a autorização é real (não temos como), mas cria o registro de que foi
declarada, reforçando que isso não é para uso informal.
"""

from database.db import log_event

SCENARIO_TEMPLATES = {
    "phishing_email": (
        "Gere um e-mail de phishing simulado realista para teste de "
        "conscientização de segurança. Inclua: remetente plausível, assunto "
        "que gera urgência ou curiosidade, corpo do e-mail, e um indicador "
        "de call-to-action (link ou anexo fictício — NÃO inclua URLs reais "
        "ou anexos executáveis, use placeholders como [LINK_DE_TESTE])."
    ),
    "vishing_script": (
        "Gere um script de ligação telefônica (vishing) para um teste de "
        "pretexting autorizado. Inclua: abertura, pretexto/personagem "
        "assumido, perguntas planejadas para extrair a informação-alvo, e "
        "respostas para objeções comuns da pessoa do outro lado."
    ),
    "pretexting_scenario": (
        "Gere um cenário de pretexting completo (não-telefônico, ex: "
        "presencial ou por e-mail) para um engagement de red team "
        "autorizado. Inclua: personagem assumido, justificativa para a "
        "interação, objetivo específico da informação/acesso buscado, e "
        "plano de saída caso a pessoa fique desconfiada."
    ),
}


def build_generation_request(
    scenario_type: str, context: str, engagement_reference: str
) -> str:
    """Monta e registra o pedido de geração de conteúdo de engenharia
    social. Retorna o prompt que o próprio agente (LLM) deve usar para
    gerar o conteúdo de fato — esta função não gera texto sozinha, só
    valida, registra a auditoria e formata o pedido."""
    from config import ALLOW_SOCIAL_ENGINEERING

    if not ALLOW_SOCIAL_ENGINEERING:
        return (
            "Geração de conteúdo de engenharia social está DESATIVADA. "
            "Para habilitar, defina ALLOW_SOCIAL_ENGINEERING=true no .env "
            "— isso é uma decisão deliberada do criador, pois envolve "
            "conteúdo de manipulação destinado a pessoas reais."
        )

    if scenario_type not in SCENARIO_TEMPLATES:
        opts = ", ".join(SCENARIO_TEMPLATES)
        return f"scenario_type inválido: {scenario_type!r}. Opções: {opts}"

    if not engagement_reference.strip():
        return (
            "engagement_reference é obrigatório (ex: número do contrato/SOW "
            "do engagement de red team autorizado) — fica registrado na "
            "trilha de auditoria junto com o conteúdo gerado."
        )

    log_event(
        "social_engineering_content_generated",
        None,
        f"scenario={scenario_type} engagement_ref={engagement_reference!r} context={context[:200]!r}",
        action_taken="gerado",
    )

    instructions = SCENARIO_TEMPLATES[scenario_type]
    return (
        f"{instructions}\n\nContexto do engagement: {context}\n\n"
        f"[Referência de autorização registrada: {engagement_reference}]\n\n"
        "LEMBRETE: isto é só o conteúdo/template. O envio ou contato real "
        "com a pessoa-alvo é sempre uma ação manual do operador humano, "
        "nunca automática."
    )
