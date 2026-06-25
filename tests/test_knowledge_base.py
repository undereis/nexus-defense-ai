import importlib

import pytest


@pytest.fixture
def kb_module(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_kb.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    import tools.knowledge_base as kb
    importlib.reload(kb)
    yield kb, dbmod


def test_ingest_rejects_empty_content(kb_module):
    kb, _ = kb_module
    result = kb.ingest("mikrotik", "Vazio", "https://example.com", "   ")
    assert "vazio" in result.lower()


def test_ingest_and_search_roundtrip(kb_module):
    kb, _ = kb_module
    kb.ingest(
        "mikrotik", "Firewall RouterOS",
        "https://wiki.mikrotik.com/wiki/Manual:IP/Firewall/Filter",
        "O firewall do RouterOS usa chains input, forward e output. "
        "A ação drop descarta pacotes silenciosamente.",
    )
    result = kb.search("firewall chains")
    assert "Firewall RouterOS" in result
    assert "wiki.mikrotik.com" in result


def test_search_no_results(kb_module):
    kb, _ = kb_module
    result = kb.search("termo que não existe em lugar nenhum xyz123")
    assert "Nenhum resultado" in result


def test_search_ranks_by_relevance(kb_module):
    kb, _ = kb_module
    kb.ingest("owasp", "SQL Injection", "https://owasp.org/sqli", "Injeção SQL é uma vulnerabilidade crítica.")
    kb.ingest("cisco", "Documento aleatório", "https://cisco.com/x", "Este documento não menciona o assunto buscado.")

    result = kb.search("injeção SQL")
    assert "SQL Injection" in result
    assert result.index("SQL Injection") < result.index("Documento aleatório") if "Documento aleatório" in result else True


def test_list_topics_empty(kb_module):
    kb, _ = kb_module
    assert "vazia" in kb.list_topics()


def test_list_topics_groups_correctly(kb_module):
    kb, _ = kb_module
    kb.ingest("mikrotik", "Doc 1", "https://x.com/1", "conteudo um")
    kb.ingest("mikrotik", "Doc 2", "https://x.com/2", "conteudo dois")
    kb.ingest("cisco", "Doc 3", "https://x.com/3", "conteudo tres")

    result = kb.list_topics()
    assert "mikrotik: 2" in result
    assert "cisco: 1" in result


def test_get_full_document(kb_module, monkeypatch):
    kb, dbmod = kb_module
    monkeypatch.setattr(dbmod, "search_knowledge", dbmod.search_knowledge)
    kb.ingest("nist", "Guia de hardening", "https://nist.gov/guide", "Conteúdo completo do guia de hardening de rede.")

    rows = dbmod.search_knowledge("hardening")
    doc_id = rows[0][0]
    result = kb.get_full_document(doc_id)
    assert "Guia de hardening" in result
    assert "Conteúdo completo do guia de hardening de rede." in result
    assert "nist.gov" in result


def test_get_full_document_not_found(kb_module):
    kb, _ = kb_module
    result = kb.get_full_document(99999)
    assert "não encontrado" in result


def test_search_handles_special_characters_safely(kb_module):
    kb, _ = kb_module
    kb.ingest("test", "Doc especial", "https://x.com", "conteudo normal")
    # não deve lançar exceção mesmo com caracteres especiais do FTS5
    result = kb.search('firewall* OR "drop" -input')
    assert isinstance(result, str)
