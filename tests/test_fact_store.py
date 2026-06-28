"""Testes para memory/fact_store.py — memória de longo prazo (Fase 7, item 1).

Fatos/decisões duráveis recuperados por relevância (FTS5), distintos da janela
rolante de conversa. clean_db monkeypatcha db.DB_PATH (object-form).
"""

import database.db as db
import pytest

from memory import fact_store as fs


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    yield


# ---------- gravar e recuperar ----------

def test_remember_and_recall():
    fs.remember_fact("O roteador de borda é um Mikrotik RB750", category="network")
    out = fs.recall_facts("mikrotik roteador")
    assert "RB750" in out


def test_recall_no_match():
    fs.remember_fact("qualquer coisa", category="fact")
    assert "Nada na memória" in fs.recall_facts("assunto inexistente xyz")


def test_recall_empty_query():
    assert "Informe um assunto" in fs.recall_facts("   ")


def test_remember_empty_content():
    assert "conteúdo vazio" in fs.remember_fact("   ")


# ---------- slug / upsert ----------

def test_explicit_slug_then_update():
    r1 = fs.remember_fact("versão antiga", slug="decisao-x", category="decision")
    assert "Memorizado" in r1
    r2 = fs.remember_fact("versão nova revisada", slug="decisao-x", category="decision")
    assert "Atualizado" in r2
    # só um fato com essa slug, e o conteúdo é o novo (FTS refletiu o update)
    rows = db.list_memory_facts()
    slugs = [r[0] for r in rows]
    assert slugs.count("decisao-x") == 1
    out = fs.recall_facts("revisada")
    assert "versão nova" in out
    # o conteúdo antigo não deve mais ser encontrado
    assert "Nada na memória" in fs.recall_facts("antiga")


def test_autoslug_is_deterministic():
    assert fs._slugify("O DNS de produção 45.187") == "o-dns-de-produ-o-45-187"


# ---------- validação / clamping ----------

def test_invalid_category_falls_back_to_fact():
    fs.remember_fact("conteudo", category="categoria-invalida", slug="s1")
    row = db.get_memory_fact("s1")
    assert row[1] == "fact"


def test_importance_is_clamped():
    fs.remember_fact("baixa", slug="lo", importance=0)
    fs.remember_fact("alta", slug="hi", importance=99)
    assert db.get_memory_fact("lo")[3] == 1
    assert db.get_memory_fact("hi")[3] == 5


def test_content_truncated():
    big = "x" * (fs._MAX_CONTENT + 500)
    fs.remember_fact(big, slug="grande")
    stored = db.get_memory_fact("grande")[2]
    assert len(stored) <= fs._MAX_CONTENT + 1  # +1 pelo caractere "…"
    assert stored.endswith("…")


# ---------- listar / panorama ----------

def test_list_empty():
    assert "Nenhum fato memorizado" in fs.list_facts()


def test_list_filter_by_category():
    fs.remember_fact("uma decisão", category="decision", slug="d1")
    fs.remember_fact("uma rede", category="network", slug="n1")
    out = fs.list_facts("decision")
    assert "d1" in out and "n1" not in out


def test_memory_overview():
    assert "vazia" in fs.memory_overview()
    fs.remember_fact("a", category="decision", slug="d")
    fs.remember_fact("b", category="network", slug="n")
    out = fs.memory_overview()
    assert "2 fato" in out
    assert "decision: 1" in out and "network: 1" in out


# ---------- esquecer (soft-delete) ----------

def test_forget_excludes_from_recall_and_block():
    fs.remember_fact("segredo operacional importante", slug="sec", category="incident")
    assert "importante" in fs.recall_facts("importante")
    assert "sec" in fs.forget_fact("sec")
    assert "Nada na memória" in fs.recall_facts("importante")
    # e não aparece no bloco de injeção
    assert "segredo operacional" not in fs.long_term_memory_block()


def test_forget_reactivates_on_remember():
    fs.remember_fact("vai e volta", slug="vv")
    fs.forget_fact("vv")
    fs.remember_fact("vai e volta de novo", slug="vv")
    assert db.get_memory_fact("vv")[5] == 1  # active


def test_forget_unknown_slug():
    assert "Nenhum fato ativo" in fs.forget_fact("nao-existe")


def test_forget_empty_slug():
    assert "Informe a slug" in fs.forget_fact("")


# ---------- recall incrementa contador ----------

def test_recall_increments_count():
    fs.remember_fact("contável", slug="cnt")
    assert db.get_memory_fact("cnt")[6] == 0  # recall_count
    fs.recall_facts("contável")
    assert db.get_memory_fact("cnt")[6] == 1


# ---------- bloco de injeção no prompt ----------

def test_long_term_block_empty_when_no_facts():
    assert fs.long_term_memory_block() == ""


def test_long_term_block_orders_by_importance():
    fs.remember_fact("menos importante", slug="lo", importance=1)
    fs.remember_fact("CRÍTICO máximo", slug="hi", importance=5)
    block = fs.long_term_memory_block()
    assert block.index("CRÍTICO") < block.index("menos importante")


# ---------- describe ----------

def test_describe_unknown():
    assert "Nenhum fato" in fs.describe_fact("xpto")


def test_describe_shows_metadata():
    fs.remember_fact("detalhe", slug="det", category="reference", importance=4)
    out = fs.describe_fact("det")
    assert "reference/det" in out
    assert "importância=4" in out
