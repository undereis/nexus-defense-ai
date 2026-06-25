"""Base de conhecimento técnico local (RAG simples via SQLite FTS5).

Guarda documentação técnica pública (RouterOS, Cisco, Huawei, OWASP,
NIST etc) indexada para busca full-text, e dá à Nexus uma forma de
consultar referência antes de responder perguntas técnicas de
segurança/administração de rede, em vez de depender só do que o modelo
já sabe de treinamento.

IMPORTANTE: só ingerimos documentação PÚBLICA e OFICIAL dos fabricantes/
organizações (wikis, guias de configuração, padrões abertos) — nunca
material de certificação com direitos autorais (provas, apostilas
pagas). O conteúdo de certificação propriamente dito não pode ser
"baixado" para esta base; se o criador tiver material próprio, pode
ser ingerido manualmente do mesmo jeito.
"""

from database.db import (
    add_knowledge_document,
    get_knowledge_document,
    list_knowledge_topics,
    search_knowledge,
)


def ingest(topic: str, title: str, source_url: str, content: str) -> str:
    """Adiciona um documento à base de conhecimento."""
    if not content.strip():
        return "Conteúdo vazio, nada para ingerir."
    doc_id = add_knowledge_document(topic, title, source_url, content)
    return f"Documento '{title}' ingerido (id={doc_id}, tópico={topic}, {len(content)} caracteres)."


def search(query: str, limit: int = 5) -> str:
    """Busca na base de conhecimento e formata os resultados."""
    rows = search_knowledge(query, limit)
    if not rows:
        return f"Nenhum resultado na base de conhecimento para: {query!r}"
    lines = [f"Resultados da base de conhecimento para {query!r}:"]
    for doc_id, topic, title, source_url, snippet in rows:
        lines.append(f"\n[{topic}] {title} (doc id={doc_id})")
        lines.append(f"  {snippet}")
        lines.append(f"  Fonte: {source_url}")
    return "\n".join(lines)


def get_full_document(doc_id: int) -> str:
    """Retorna o conteúdo completo de um documento (use depois de search()
    para ler mais contexto do que o snippet)."""
    row = get_knowledge_document(doc_id)
    if not row:
        return f"Documento id={doc_id} não encontrado."
    topic, title, source_url, content, fetched_at = row
    return f"[{topic}] {title}\nFonte: {source_url} (obtido em {fetched_at})\n\n{content}"


def list_topics() -> str:
    """Lista os tópicos disponíveis na base de conhecimento, com contagem."""
    rows = list_knowledge_topics()
    if not rows:
        return "Base de conhecimento vazia ainda."
    lines = ["Tópicos na base de conhecimento:"]
    for topic, total in rows:
        lines.append(f"  {topic}: {total} documento(s)")
    return "\n".join(lines)
