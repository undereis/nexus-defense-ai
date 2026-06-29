"""Testes da fatia 2B (Fase 6): captura do User-Agent no honeypot HTTP.

Antes, o honeypot HTTP lia o request e DESCARTAVA o User-Agent; agora ele o
extrai e persiste em honeypot_hits, alimentando o fingerprint da ferramenta do
atacante (tools/tool_fingerprint.py) com sua fonte mais rica.

Sem socket: testa a função pura de extração, a persistência/getter no DB e a
união da fonte no fingerprint — nada abre porta de rede.
"""

import pytest

import database.db as db_module
from tools import honeypot
from tools.tool_fingerprint import fingerprint_tools_for_ip


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    db_module.init_db()
    yield


# ---------- extração pura ----------

def test_extract_user_agent_basic():
    req = b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: sqlmap/1.5.2\r\n\r\n"
    assert honeypot._extract_user_agent(req) == "sqlmap/1.5.2"


def test_extract_user_agent_absent_is_none():
    req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    assert honeypot._extract_user_agent(req) is None


def test_extract_user_agent_case_insensitive_and_stripped():
    req = b"POST /login HTTP/1.1\r\nuser-agent:   Nmap Scripting Engine  \r\n\r\n"
    assert honeypot._extract_user_agent(req) == "Nmap Scripting Engine"


# ---------- persistência + getter ----------

def test_record_and_get_honeypot_user_agents_distinct():
    db_module.record_honeypot_hit("203.0.113.9", 8081, "http", "sqlmap/1.5")
    db_module.record_honeypot_hit("203.0.113.9", 8081, "http", "sqlmap/1.5")  # repetido
    db_module.record_honeypot_hit("203.0.113.9", 8081, "http", "curl/8.0")
    db_module.record_honeypot_hit("203.0.113.9", 22, "ssh")  # sem UA

    uas = db_module.get_honeypot_user_agents_for_ip("203.0.113.9")
    assert uas == ["curl/8.0", "sqlmap/1.5"]  # distintos, mais recente primeiro


def test_record_without_user_agent_stays_null():
    db_module.record_honeypot_hit("203.0.113.10", 2222, "ssh")
    assert db_module.get_honeypot_user_agents_for_ip("203.0.113.10") == []


# ---------- integração no fingerprint ----------

def test_fingerprint_picks_up_honeypot_user_agent():
    db_module.record_honeypot_hit("203.0.113.11", 8081, "http", "sqlmap/1.6#dev")

    fp = fingerprint_tools_for_ip("203.0.113.11")

    assert fp["has_signal"] is True
    tools = [c["tool"] for c in fp["user_agents"]]
    assert "sqlmap" in tools


def test_process_hit_persists_user_agent_end_to_end():
    """_process_hit (chamado pelo honeypot ao fim de cada conexão) deve gravar
    o UA que o handler HTTP retornou."""
    honeypot._process_hit("203.0.113.12", 8081, "http", "Hydra/9.0")
    assert db_module.get_honeypot_user_agents_for_ip("203.0.113.12") == ["Hydra/9.0"]
