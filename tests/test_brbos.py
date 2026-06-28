"""Testes para tools/brbos.py — integração com o SO de DNS BrbOS.

Toda a camada HTTP é mockada por monkeypatch object-form nos seams
_api_get / _api_post (e o gate via tools.risk), então os testes não tocam a
rede nem dependem dos caminhos exatos dos endpoints (_EP_*, ainda a calibrar
contra a caixa real). Os toggles/credenciais são globais do módulo brbos
(importados de config) e também patcheados object-form.
"""

import database.db as db
import pytest

from tools import brbos, risk


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db, "DB_PATH", db_path)
    db.init_db()
    yield


def _configure(monkeypatch, allow=True):
    """Deixa o BrbOS 'configurado' (host/user/senha) e liga/desliga a escrita."""
    monkeypatch.setattr(brbos, "BRBOS_HOST", "10.0.0.1")
    monkeypatch.setattr(brbos, "BRBOS_USER", "admin")
    monkeypatch.setattr(brbos, "BRBOS_PASSWORD", "secret")
    monkeypatch.setattr(brbos, "ALLOW_BRBOS_BLOCK", allow)


# ---------- config / helpers puros ----------

def test_is_configured(monkeypatch):
    monkeypatch.setattr(brbos, "BRBOS_HOST", "")
    assert brbos.is_configured() is False
    monkeypatch.setattr(brbos, "BRBOS_HOST", "10.0.0.1")
    monkeypatch.setattr(brbos, "BRBOS_USER", "admin")
    monkeypatch.setattr(brbos, "BRBOS_PASSWORD", "x")
    assert brbos.is_configured() is True


def test_normalize_domain():
    assert brbos._normalize_domain("HTTP://Bad.COM/path?x=1") == "bad.com"
    assert brbos._normalize_domain("  evil.example.  ") == "evil.example"
    assert brbos._normalize_domain("user@mail.example.org") == "mail.example.org"
    assert brbos._normalize_domain("no-dot") == ""
    assert brbos._normalize_domain("a b c") == ""
    assert brbos._normalize_domain("") == ""


def test_is_protected_domain(monkeypatch):
    monkeypatch.setattr(brbos, "BRBOS_PROTECTED_DOMAINS", "xfiber.com.br, xfiber.local")
    assert brbos._is_protected_domain("xfiber.com.br") is True       # exato
    assert brbos._is_protected_domain("mail.xfiber.com.br") is True  # sob o sufixo
    assert brbos._is_protected_domain("olt01.xfiber.local") is True
    assert brbos._is_protected_domain("notxfiber.com.br") is False   # não é sufixo de label
    assert brbos._is_protected_domain("xfiber.com.br.evil.com") is False  # impostor


def test_extract_metrics_aliases_and_data_wrapper():
    m = brbos._extract_dns_metrics(
        {"data": {"requests": 9, "cache_hit": 4, "cache_miss": 1, "nx": 2}}
    )
    assert m == {"total_req": 9, "hit": 4, "miss": 1, "nxdomain": 2}
    # dict plano + valores numéricos em string
    m2 = brbos._extract_dns_metrics({"total_req": "100", "hit": "80"})
    assert m2["total_req"] == 100 and m2["hit"] == 80
    assert m2["miss"] is None and m2["nxdomain"] is None


# ---------- estatísticas (leitura) ----------

def test_get_dns_stats_happy_and_snapshot(monkeypatch):
    monkeypatch.setattr(brbos, "BRBOS_HOST", "10.0.0.1")
    monkeypatch.setattr(
        brbos, "_api_get",
        lambda path, params=None: {"req": 100, "hit": 80, "miss": 20, "nxdomain": 5},
    )
    report = brbos.get_dns_stats()
    assert "REQ: 100" in report
    assert "NXDOMAIN: 5" in report
    assert "cache hit ~80%" in report
    # gravou o snapshot na série temporal
    rows = db.list_brbos_dns_stats("10.0.0.1")
    assert len(rows) == 1
    assert rows[0][2] == 100  # total_req


def test_get_dns_stats_error(monkeypatch):
    monkeypatch.setattr(brbos, "BRBOS_HOST", "10.0.0.1")
    monkeypatch.setattr(
        brbos, "_api_get", lambda path, params=None: {"_error": "falha de conexão"}
    )
    out = brbos.get_dns_stats()
    assert "falha de conexão" in out
    # erro não grava snapshot
    assert db.list_brbos_dns_stats("10.0.0.1") == []


def test_get_dns_stats_unmapped_fields(monkeypatch):
    monkeypatch.setattr(brbos, "BRBOS_HOST", "10.0.0.1")
    monkeypatch.setattr(
        brbos, "_api_get", lambda path, params=None: {"foo": 1, "bar": 2}
    )
    out = brbos.get_dns_stats()
    assert "não foram mapeados" in out


# ---------- RPZ / rate limit (leitura) ----------

def test_list_rpz(monkeypatch):
    monkeypatch.setattr(
        brbos, "_api_get",
        lambda path, params=None: {"data": [{"name": "bad.com", "action": "nxdomain"}]},
    )
    out = brbos.list_rpz()
    assert "bad.com" in out and "nxdomain" in out


def test_list_rpz_error(monkeypatch):
    monkeypatch.setattr(
        brbos, "_api_get", lambda path, params=None: {"_error": "HTTP 500"}
    )
    assert "HTTP 500" in brbos.list_rpz()


def test_ratelimit_status(monkeypatch):
    monkeypatch.setattr(brbos, "BRBOS_HOST", "10.0.0.1")
    monkeypatch.setattr(
        brbos, "_api_get", lambda path, params=None: {"limit": 100, "window": "1s"}
    )
    out = brbos.ratelimit_status()
    assert "limit" in out and "100" in out


# ---------- bloqueio de domínio: guardas ----------

def test_block_domain_requires_toggle(monkeypatch):
    _configure(monkeypatch, allow=False)
    out = brbos.block_domain("bad.com")
    assert "ALLOW_BRBOS_BLOCK" in out


def test_block_domain_not_configured(monkeypatch):
    monkeypatch.setattr(brbos, "ALLOW_BRBOS_BLOCK", True)
    monkeypatch.setattr(brbos, "BRBOS_HOST", "")
    out = brbos.block_domain("bad.com")
    assert "não configurado" in out


def test_block_domain_invalid(monkeypatch):
    _configure(monkeypatch)
    assert "inválido" in brbos.block_domain("not a domain")


def test_block_domain_invalid_policy(monkeypatch):
    _configure(monkeypatch)
    assert "Política RPZ inválida" in brbos.block_domain("bad.com", policy="evil")


def test_block_domain_protected_refused(monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setattr(brbos, "BRBOS_PROTECTED_DOMAINS", "xfiber.com.br,xfiber.local")
    assert "RECUSADO" in brbos.block_domain("ns1.xfiber.com.br")
    assert "RECUSADO" in brbos.block_domain("xfiber.local")
    # normaliza antes de checar: scheme/caixa não driblam a proteção
    assert "RECUSADO" in brbos.block_domain("HTTPS://NS1.XFIBER.COM.BR/x")


def test_block_domain_already_blocked(monkeypatch):
    _configure(monkeypatch)
    db.record_brbos_rpz_action("dup.com", "block", "nxdomain", "x")
    assert "já consta" in brbos.block_domain("dup.com")


# ---------- bloqueio de domínio: gate (não executa direto) ----------

def test_block_domain_goes_to_gate(monkeypatch):
    _configure(monkeypatch)
    called = {"post": False}
    monkeypatch.setattr(
        brbos, "_api_post",
        lambda *a, **k: called.__setitem__("post", True) or {"success": True},
    )
    out = brbos.block_domain("phish.example", reason="phishing")
    assert "ALTO RISCO" in out and "pendente de confirmação" in out
    # NÃO executou: não chamou a API nem registrou nada
    assert called["post"] is False
    assert db.get_brbos_rpz_action("phish.example") is None


def test_block_domain_full_gate_flow(monkeypatch):
    _configure(monkeypatch)
    # registra o executor real no gate (em produção quem faz isso é o agente)
    risk.register_action("brbos_block_domain", brbos._execute_block_domain)
    posted = {}
    monkeypatch.setattr(
        brbos, "_api_post",
        lambda path, data=None: posted.update(data or {}) or {"success": True},
    )
    msg = brbos.block_domain("evil.example", reason="C2")
    assert "pendente de confirmação" in msg
    assert db.get_brbos_rpz_action("evil.example") is None  # ainda não executou

    # canal fora de banda: pega id + código direto do banco
    pend = db.list_pending_actions()
    assert len(pend) == 1
    action_id = pend[0][0]
    code = db.get_pending_action(action_id)[4]

    out = risk.confirm_and_execute(action_id, code)
    assert "confirmada e executada" in out
    assert "evil.example" in out
    # agora sim: aplicou no BrbOS e registrou na auditoria local
    assert posted.get("name") == "evil.example"
    assert db.get_brbos_rpz_action("evil.example") is not None


def test_block_domain_wrong_code_does_not_execute(monkeypatch):
    _configure(monkeypatch)
    risk.register_action("brbos_block_domain", brbos._execute_block_domain)
    called = {"post": False}
    monkeypatch.setattr(
        brbos, "_api_post",
        lambda *a, **k: called.__setitem__("post", True) or {"success": True},
    )
    brbos.block_domain("evil.example", reason="C2")
    action_id = db.list_pending_actions()[0][0]
    out = risk.confirm_and_execute(action_id, "000000")
    assert "incorreto" in out
    assert called["post"] is False
    assert db.get_brbos_rpz_action("evil.example") is None


# ---------- executor real (registrado no gate) ----------

def test_execute_block_domain_records(monkeypatch):
    monkeypatch.setattr(brbos, "BRBOS_HOST", "10.0.0.1")
    monkeypatch.setattr(brbos, "_api_post", lambda path, data=None: {"success": True})
    out = brbos._execute_block_domain("c2.example", "nxdomain", "C2")
    assert "bloqueado" in out
    row = db.get_brbos_rpz_action("c2.example")
    assert row is not None
    assert row[2] == "nxdomain"  # policy


def test_execute_block_domain_api_error(monkeypatch):
    monkeypatch.setattr(brbos, "BRBOS_HOST", "10.0.0.1")
    monkeypatch.setattr(brbos, "_api_post", lambda path, data=None: {"_error": "timeout"})
    out = brbos._execute_block_domain("c2.example", "nxdomain", "")
    assert "Falha" in out
    assert db.get_brbos_rpz_action("c2.example") is None  # falha não registra


def test_execute_block_domain_brbos_refused(monkeypatch):
    monkeypatch.setattr(brbos, "BRBOS_HOST", "10.0.0.1")
    monkeypatch.setattr(brbos, "_api_post", lambda path, data=None: {"success": False})
    out = brbos._execute_block_domain("c2.example", "nxdomain", "")
    assert "recusou" in out
    assert db.get_brbos_rpz_action("c2.example") is None


# ---------- desbloqueio (de-escalação, sem gate) ----------

def test_unblock_domain_not_blocked():
    assert "não está na lista" in brbos.unblock_domain("ghost.com")


def test_unblock_domain_success(monkeypatch):
    monkeypatch.setattr(brbos, "BRBOS_HOST", "10.0.0.1")
    db.record_brbos_rpz_action("bad.com", "block", "nxdomain", "x")
    monkeypatch.setattr(brbos, "_api_post", lambda path, data=None: {"success": True})
    out = brbos.unblock_domain("bad.com")
    assert "desbloqueado" in out
    assert db.get_brbos_rpz_action("bad.com") is None


# ---------- auditoria local ----------

def test_list_blocked_domains(monkeypatch):
    assert "Nenhum" in brbos.list_blocked_domains()
    db.record_brbos_rpz_action("bad.com", "block", "nxdomain", "C2 conhecido")
    out = brbos.list_blocked_domains()
    assert "bad.com" in out and "C2 conhecido" in out
