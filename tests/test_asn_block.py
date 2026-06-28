"""Testes para tools/asn_block.py — bloqueio de ASN inteiro.

Tudo mockado: sem chamadas reais a RIPEstat, sem pfctl/iptables reais.
Verifica:
- Gate de autorização (ALLOW_ASN_BLOCK=false rejeita na entrada)
- Validação de ASN (regex + normalização)
- Fluxo completo: prefixos → gate → execute → DB
- Desbloqueio e listagem
"""

import importlib
import json

import pytest


@pytest.fixture
def asn_mod(monkeypatch, tmp_path):
    import config as cfg
    monkeypatch.setattr(cfg, "DB_PATH", tmp_path / "test_asn.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    monkeypatch.setattr(cfg, "ALLOW_ASN_BLOCK", False)
    import tools.asn_block as asn_block
    importlib.reload(asn_block)
    yield asn_block, dbmod, cfg


# ---------- gate de autorização ----------

def test_disabled_by_default(asn_mod):
    asn_block, _, _ = asn_mod
    result = asn_block.request_asn_block("AS15169")
    assert "ALLOW_ASN_BLOCK" in result


def test_disabled_rejects_immediately(asn_mod, monkeypatch):
    """Com ALLOW_ASN_BLOCK=false, nenhuma chamada de rede deve ocorrer."""
    asn_block, _, _ = asn_mod
    net_calls = []
    monkeypatch.setattr("tools.asn_block.get_asn_prefixes",
                        lambda asn: net_calls.append(asn) or [])
    asn_block.request_asn_block("AS15169")
    assert net_calls == []


# ---------- validação de ASN ----------

def test_invalid_asn_rejected(asn_mod, monkeypatch):
    asn_block, _, cfg = asn_mod
    monkeypatch.setattr(cfg, "ALLOW_ASN_BLOCK", True)
    importlib.reload(asn_block)
    result = asn_block.request_asn_block("not-an-asn")
    assert "inválido" in result


def test_asn_number_normalized_to_as_prefix(asn_mod, monkeypatch):
    """'15169' deve ser normalizado para 'AS15169'."""
    asn_block, _, cfg = asn_mod
    monkeypatch.setattr(cfg, "ALLOW_ASN_BLOCK", True)
    prefixes = ["203.0.113.0/24"]
    gate_calls = []
    monkeypatch.setattr("tools.asn_block.get_asn_prefixes", lambda asn: prefixes)
    monkeypatch.setattr("tools.asn_block.risk_gate.request_confirmation",
                        lambda name, summary, **kw: gate_calls.append(kw) or "pendente")
    importlib.reload(asn_block)

    asn_block.request_asn_block("15169")
    assert gate_calls[0]["asn"] == "AS15169"


# ---------- fluxo completo ----------

def test_no_prefixes_returns_error(asn_mod, monkeypatch):
    asn_block, _, cfg = asn_mod
    monkeypatch.setattr(cfg, "ALLOW_ASN_BLOCK", True)
    monkeypatch.setattr("tools.asn_block.get_asn_prefixes", lambda asn: [])
    importlib.reload(asn_block)

    result = asn_block.request_asn_block("AS99999")
    assert "nenhum prefixo" in result.lower()


def test_valid_asn_queues_gate(asn_mod, monkeypatch):
    asn_block, _, cfg = asn_mod
    # Patch direto no binding do módulo (não via cfg + reload, que desfaria
    # outros patches na mesma jogada).
    monkeypatch.setattr(asn_block, "ALLOW_ASN_BLOCK", True)
    monkeypatch.setattr(asn_block, "get_asn_prefixes",
                        lambda asn: ["203.0.113.0/24", "198.51.100.0/24"])
    gate_calls = []
    monkeypatch.setattr(asn_block.risk_gate, "request_confirmation",
                        lambda name, summary, **kw: gate_calls.append((name, kw)) or "pendente")

    result = asn_block.request_asn_block("AS64496", "fonte de ataque recorrente")
    assert len(gate_calls) == 1
    assert gate_calls[0][0] == "asn_block_execute"
    assert gate_calls[0][1]["asn"] == "AS64496"
    assert gate_calls[0][1]["description"] == "fonte de ataque recorrente"
    assert "pendente" in result


def test_already_blocked_skips_gate(asn_mod, monkeypatch):
    asn_block, dbmod, cfg = asn_mod
    monkeypatch.setattr(cfg, "ALLOW_ASN_BLOCK", True)
    dbmod.record_asn_block("AS64496", "teste", ["203.0.113.0/24"])
    importlib.reload(asn_block)

    result = asn_block.request_asn_block("AS64496")
    assert "já está bloqueado" in result


# ---------- _execute_block ----------

def test_execute_block_blocks_all_prefixes(asn_mod, monkeypatch):
    asn_block, dbmod, _ = asn_mod
    blocked_cidrs = []
    monkeypatch.setattr("tools.asn_block.get_asn_prefixes",
                        lambda asn: ["10.0.0.0/24", "10.1.0.0/24"])
    monkeypatch.setattr("tools.asn_block.firewall.block_cidr",
                        lambda cidr, reason="": blocked_cidrs.append(cidr) or f"CIDR {cidr} bloqueado.")

    result = asn_block._execute_block("AS64496", "teste")
    assert len(blocked_cidrs) == 2
    assert "10.0.0.0/24" in blocked_cidrs
    assert "10.1.0.0/24" in blocked_cidrs
    assert "2/2" in result


def test_execute_block_records_in_db(asn_mod, monkeypatch):
    asn_block, dbmod, _ = asn_mod
    monkeypatch.setattr("tools.asn_block.get_asn_prefixes",
                        lambda asn: ["203.0.113.0/24"])
    monkeypatch.setattr("tools.asn_block.firewall.block_cidr",
                        lambda cidr, reason="": f"CIDR {cidr} bloqueado.")

    asn_block._execute_block("AS64496", "teste")
    row = dbmod.get_asn_block("AS64496")
    assert row is not None
    assert json.loads(row[1]) == ["203.0.113.0/24"]


def test_execute_block_no_prefixes(asn_mod, monkeypatch):
    asn_block, _, _ = asn_mod
    monkeypatch.setattr("tools.asn_block.get_asn_prefixes", lambda asn: [])
    result = asn_block._execute_block("AS99999", "vazio")
    assert "nenhum prefixo" in result.lower()


# ---------- unblock_asn ----------

def test_unblock_unknown_asn(asn_mod):
    asn_block, _, _ = asn_mod
    result = asn_block.unblock_asn("AS99999")
    assert "não está na lista" in result


def test_unblock_removes_cidrs_and_db_entry(asn_mod, monkeypatch):
    asn_block, dbmod, _ = asn_mod
    dbmod.record_asn_block("AS64496", "teste", ["10.0.0.0/24", "10.1.0.0/24"])

    unblocked = []
    monkeypatch.setattr("tools.asn_block.firewall.unblock_cidr",
                        lambda cidr: unblocked.append(cidr) or f"CIDR {cidr} desbloqueado.")

    result = asn_block.unblock_asn("AS64496")
    assert len(unblocked) == 2
    assert dbmod.get_asn_block("AS64496") is None
    assert "2/2" in result


# ---------- list_blocked_asns ----------

def test_list_empty(asn_mod):
    asn_block, _, _ = asn_mod
    assert "Nenhum ASN" in asn_block.list_blocked_asns()


def test_list_shows_blocked(asn_mod, monkeypatch):
    asn_block, dbmod, _ = asn_mod
    dbmod.record_asn_block("AS64496", "atacante frequente", ["10.0.0.0/24"])
    result = asn_block.list_blocked_asns()
    assert "AS64496" in result
    assert "atacante frequente" in result
