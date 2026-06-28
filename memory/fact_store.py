"""Memória institucional de longo prazo da Nexus (Fase 7, item 1).

Distinta de memory/memory_store.py (a janela rolante das últimas N mensagens
de conversa): aqui ficam os FATOS e DECISÕES duráveis que o operador não quer
reexplicar nunca mais — quem é quem, topologia da rede, escolhas tomadas,
preferências, lições de incidentes. São recuperados por relevância (FTS5), não
por ordem cronológica, e sobrevivem indefinidamente entre sessões.

Dois caminhos de uso:
  1. Injeção automática: no início de cada sessão, os fatos mais importantes
     entram no system prompt (long_term_memory_block) — a Nexus "já sabe".
  2. Recall sob demanda: durante a conversa, recall_facts(query) busca o que
     for relevante ao assunto atual, mesmo que esteja fora do top injetado.

A Nexus deve gravar um fato sempre que o operador tomar uma decisão durável,
declarar uma preferência, ou revelar algo sobre a rede que valha lembrar.
"""

import re

from database.db import (
    count_memory_facts,
    count_memory_facts_by_category,
    forget_memory_fact,
    get_memory_fact,
    get_top_memory_facts,
    list_memory_facts,
    search_memory_facts,
    touch_memory_recall,
    upsert_memory_fact,
)

# Categorias canônicas. 'fact' é o fallback genérico.
CATEGORIES = {"decision", "preference", "network", "incident", "reference", "fact"}
_MAX_CONTENT = 2000
_DEFAULT_IMPORTANCE = 3


def _slugify(text: str, max_words: int = 7) -> str:
    """Gera uma slug kebab-case estável a partir do conteúdo (primeiras
    palavras). Usada quando o chamador não fornece uma slug explícita."""
    words = re.findall(r"[a-z0-9]+", text.lower())
    slug = "-".join(words[:max_words])
    return slug[:80] or "fato"


def _clamp_importance(importance: int) -> int:
    try:
        return max(1, min(5, int(importance)))
    except (TypeError, ValueError):
        return _DEFAULT_IMPORTANCE


def remember_fact(content: str, category: str = "fact", slug: str = "",
                  importance: int = _DEFAULT_IMPORTANCE,
                  source: str = "operador") -> str:
    """Grava (ou atualiza) um fato durável na memória de longo prazo.
    category: decision, preference, network, incident, reference ou fact.
    importance: 1 (trivial) a 5 (crítico) — guia o que é injetado por padrão."""
    content = (content or "").strip()
    if not content:
        return "Nada a lembrar: conteúdo vazio."
    if len(content) > _MAX_CONTENT:
        content = content[:_MAX_CONTENT].rstrip() + "…"
    category = (category or "fact").strip().lower()
    if category not in CATEGORIES:
        category = "fact"
    importance = _clamp_importance(importance)
    slug = (slug or "").strip().lower() or _slugify(content)
    result = upsert_memory_fact(slug, category, content, importance, source)
    verb = "Memorizado" if result == "created" else "Atualizado"
    return f"{verb} [{category}/{slug}] (importância {importance}): {content}"


def recall_facts(query: str, limit: int = 8) -> str:
    """Busca na memória de longo prazo os fatos relevantes a um assunto.
    Marca o que foi recuperado (aprende o que é útil com o tempo)."""
    query = (query or "").strip()
    if not query:
        return "Informe um assunto para buscar na memória."
    rows = search_memory_facts(query, limit)
    if not rows:
        return f"Nada na memória de longo prazo sobre '{query}'."
    touch_memory_recall([r[0] for r in rows])
    lines = [f"Memória de longo prazo sobre '{query}':"]
    for slug, category, content, importance, _snippet in rows:
        lines.append(f"  • [{category}/{slug}] (imp {importance}) {content}")
    return "\n".join(lines)


def list_facts(category: str = "") -> str:
    """Lista os fatos memorizados, opcionalmente filtrados por categoria."""
    category = (category or "").strip().lower() or None
    rows = list_memory_facts(category=category)
    if not rows:
        scope = f" na categoria '{category}'" if category else ""
        return f"Nenhum fato memorizado{scope}."
    lines = [f"Fatos na memória de longo prazo ({len(rows)}):"]
    for slug, cat, content, importance, source, _active, recall_count, _c, updated in rows:
        lines.append(
            f"  [{cat}/{slug}] (imp {importance}, recuperado {recall_count}x, "
            f"atualizado {updated[:10]}) — {content}"
        )
    return "\n".join(lines)


def forget_fact(slug: str) -> str:
    """Esquece (soft-delete) um fato pela slug. Não apaga fisicamente —
    desativa, então deixa de ser recuperado/injetado."""
    slug = (slug or "").strip().lower()
    if not slug:
        return "Informe a slug do fato a esquecer."
    if forget_memory_fact(slug):
        return f"Fato '{slug}' esquecido (desativado)."
    return f"Nenhum fato ativo com slug '{slug}'."


def describe_fact(slug: str) -> str:
    """Mostra um fato específico em detalhe."""
    slug = (slug or "").strip().lower()
    row = get_memory_fact(slug)
    if row is None:
        return f"Nenhum fato com slug '{slug}'."
    (s, category, content, importance, source, active, recall_count,
     created, updated, last_recalled) = row
    return (
        f"[{category}/{s}] {'(ATIVO)' if active else '(esquecido)'}\n"
        f"  {content}\n"
        f"  importância={importance} · fonte={source or '—'} · "
        f"recuperado {recall_count}x\n"
        f"  criado {created[:19]} · atualizado {updated[:19]}"
        + (f" · último recall {last_recalled[:19]}" if last_recalled else "")
    )


def memory_overview() -> str:
    """Panorama da memória de longo prazo: total e quebra por categoria."""
    total = count_memory_facts()
    if total == 0:
        return "Memória de longo prazo vazia — nenhum fato/decisão memorizado ainda."
    by_cat = count_memory_facts_by_category()
    lines = [f"Memória de longo prazo: {total} fato(s) ativo(s)."]
    for category, n in by_cat:
        lines.append(f"  {category}: {n}")
    return "\n".join(lines)


def long_term_memory_block(limit: int = 12) -> str:
    """Bloco de texto com os fatos mais importantes, para injetar no system
    prompt no início de cada sessão. Vazio se não há nada memorizado (não
    polui o prompt)."""
    rows = get_top_memory_facts(limit)
    if not rows:
        return ""
    lines = ["MEMÓRIA DE LONGO PRAZO (fatos/decisões duráveis que você já sabe):"]
    for slug, category, content, _importance in rows:
        lines.append(f"  - [{category}] {content}")
    lines.append(
        "Use recall_memory(assunto) para buscar fatos além destes, e "
        "remember_fact(...) quando o operador decidir/revelar algo durável."
    )
    return "\n".join(lines)
