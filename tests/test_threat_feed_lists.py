"""Testes para tools/threat_feed_lists.py — listas globais de IPs
maliciosos (Spamhaus DROP, Feodo Tracker, Emerging Threats).

O PARSER de texto de feed é testado de verdade contra formatos reais
(comentários com ';', '#', linhas vazias) — sem mock. refresh_feed via
rede é mockado para não depender de internet/rate-limit em CI; já foi
validado manualmente contra os 3 feeds reais antes deste commit (ver
mensagem do commit)."""

import importlib

import pytest

from tools import threat_feed_lists as feeds


@pytest.fixture
def db_module(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_feeds.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()
    importlib.reload(feeds)
    yield dbmod


def test_parse_feed_text_spamhaus_format():
    text = (
        "; Spamhaus DROP list\n"
        "1.10.16.0/20 ; SBL12345\n"
        "1.19.0.0/16 ; SBL67890\n"
        "\n"
        "# comentário alternativo\n"
        "203.0.113.0/24 ; SBL11111\n"
    )
    entries = feeds._parse_feed_text(text)
    assert entries == ["1.10.16.0/20", "1.19.0.0/16", "203.0.113.0/24"]


def test_parse_feed_text_plain_ip_list():
    text = "198.51.100.5\n203.0.113.9\n\n# nada aqui\n"
    entries = feeds._parse_feed_text(text)
    assert entries == ["198.51.100.5", "203.0.113.9"]


def test_parse_feed_text_ignores_garbage_lines():
    text = "not an ip\n198.51.100.5\nalso garbage; with semicolon\n"
    entries = feeds._parse_feed_text(text)
    assert "198.51.100.5" in entries
    assert "not" not in entries


def test_refresh_feed_unknown_source(db_module):
    result = feeds.refresh_feed("nao_existe")
    assert "Fonte desconhecida" in result


def test_refresh_feed_network_failure(db_module, monkeypatch):
    import requests
    def raise_error(*a, **k):
        raise requests.RequestException("boom")
    monkeypatch.setattr(feeds.requests, "get", raise_error)

    result = feeds.refresh_feed("spamhaus_drop")
    assert "Falha ao baixar" in result


def test_refresh_feed_stores_entries(db_module, monkeypatch):
    class FakeResp:
        text = "203.0.113.0/24 ; SBL1\n198.51.100.5\n"
        def raise_for_status(self):
            pass
    monkeypatch.setattr(feeds.requests, "get", lambda *a, **k: FakeResp())

    result = feeds.refresh_feed("feodo_tracker")
    assert "2 entrada(s)" in result

    status = feeds.describe_feed_status()
    assert "feodo_tracker: 2 entrada(s)" in status


def test_check_ip_against_feeds_matches_cidr(db_module, monkeypatch):
    class FakeResp:
        text = "203.0.113.0/24\n"
        def raise_for_status(self):
            pass
    monkeypatch.setattr(feeds.requests, "get", lambda *a, **k: FakeResp())
    feeds.refresh_feed("spamhaus_drop")

    matches = feeds.check_ip_against_feeds("203.0.113.55")
    assert matches == ["spamhaus_drop"]


def test_check_ip_against_feeds_no_match(db_module, monkeypatch):
    class FakeResp:
        text = "203.0.113.0/24\n"
        def raise_for_status(self):
            pass
    monkeypatch.setattr(feeds.requests, "get", lambda *a, **k: FakeResp())
    feeds.refresh_feed("spamhaus_drop")

    matches = feeds.check_ip_against_feeds("8.8.8.8")
    assert matches == []


def test_check_ip_against_feeds_invalid_ip(db_module):
    assert feeds.check_ip_against_feeds("not-an-ip") == []


def test_describe_ip_feed_check_text(db_module, monkeypatch):
    class FakeResp:
        text = "203.0.113.0/24\n"
        def raise_for_status(self):
            pass
    monkeypatch.setattr(feeds.requests, "get", lambda *a, **k: FakeResp())
    feeds.refresh_feed("spamhaus_drop")

    assert "ENCONTRADO" in feeds.describe_ip_feed_check("203.0.113.1")
    assert "não encontrado" in feeds.describe_ip_feed_check("8.8.8.8")


def test_describe_feed_status_empty(db_module):
    assert "Nenhum feed" in feeds.describe_feed_status()


def test_refresh_one_feed_failure_does_not_block_others(db_module, monkeypatch):
    def fake_get(url, **kwargs):
        class FakeResp:
            def raise_for_status(self):
                if "spamhaus" in url:
                    raise feeds.requests.RequestException("spamhaus indisponível")
            text = "198.51.100.0/24\n"
        return FakeResp()

    monkeypatch.setattr(feeds.requests, "get", fake_get)
    result = feeds.refresh_all_feeds()
    assert "Falha ao baixar feed spamhaus_drop" in result
    assert "feodo_tracker atualizado" in result
    assert "emerging_threats atualizado" in result
