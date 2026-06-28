"""Testes para tools/client_risk.py — modelo de risco por cliente (Fase 7, item 3).

Cobre a agregação de sinais persistidos (reputação, honeypot, IPs bloqueados)
pelo CIDR do cliente, as faixas de tier, o z-threshold ajustado (com piso) e os
relatórios textuais. Sinais fora do CIDR do cliente devem ser ignorados.
"""

import pytest

import database.db as db_module
from tools import client_baseline, client_risk

# CIDR do cliente sob teste (TEST-NET-3) e IPs dentro/fora dele.
_CIDR = "203.0.113.0/24"
_IN_A = "203.0.113.5"
_IN_B = "203.0.113.6"
_IN_C = "203.0.113.7"
_OUT = "198.51.100.9"


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    db_module.init_db()
    yield


def _register():
    client_baseline.add_client_profile("xfiber-teste", _CIDR, "Cliente de teste")


# ---- risk_tier (função pura de faixa) ----

def test_tier_baixo():
    assert client_risk.risk_tier(0) == "baixo"


def test_tier_medio_lower_boundary():
    assert client_risk.risk_tier(1) == "médio"


def test_tier_medio_upper_boundary():
    assert client_risk.risk_tier(19) == "médio"


def test_tier_alto_boundary():
    assert client_risk.risk_tier(20) == "alto"


# ---- compute_client_risk ----

def test_compute_unknown_client_returns_none():
    assert client_risk.compute_client_risk("nao-existe") is None


def test_compute_no_signals_score_zero_baixo():
    _register()
    risk = client_risk.compute_client_risk("xfiber-teste")
    assert risk is not None
    assert risk["score"] == 0
    assert risk["tier"] == "baixo"
    assert risk["cidr"] == _CIDR


def test_reputation_signal_counts():
    _register()
    # 1 isolamento = reputation_score(0,1) = 10; 1 flag = reputation_score(1,0) = 2.
    db_module.record_threat_isolation(_IN_A)  # times_isolated = 1
    db_module.record_threat_flag(_IN_B)       # times_flagged = 1
    risk = client_risk.compute_client_risk("xfiber-teste")
    assert risk["reputation_sum"] == 12  # 10 + 2
    assert risk["reputation_ips"] == 2
    assert risk["score"] == 12
    assert risk["tier"] == "médio"


def test_honeypot_signal_counts():
    _register()
    # IP A toca honeypot 3 vezes, IP B 1 vez => 2 IPs, 4 hits.
    for _ in range(3):
        db_module.record_honeypot_hit(_IN_A, 22, "ssh")
    db_module.record_honeypot_hit(_IN_B, 23, "telnet")
    risk = client_risk.compute_client_risk("xfiber-teste")
    assert risk["honeypot_ips"] == 2
    assert risk["honeypot_hits"] == 4
    # score = 2*15 + 4*1 = 34
    assert risk["score"] == 34
    assert risk["tier"] == "alto"


def test_blocked_signal_counts():
    _register()
    db_module.record_blocked_ip(_IN_A, "teste")
    db_module.record_blocked_ip(_IN_B, "teste")
    risk = client_risk.compute_client_risk("xfiber-teste")
    assert risk["blocked_ips"] == 2
    assert risk["score"] == 10  # 2 * 5
    assert risk["tier"] == "médio"


def test_signals_outside_cidr_are_ignored():
    _register()
    db_module.record_threat_isolation(_OUT)
    db_module.record_honeypot_hit(_OUT, 22, "ssh")
    db_module.record_blocked_ip(_OUT, "teste")
    risk = client_risk.compute_client_risk("xfiber-teste")
    assert risk["score"] == 0
    assert risk["tier"] == "baixo"


def test_combined_signals_sum():
    _register()
    db_module.record_threat_isolation(_IN_A)        # reputação 10
    db_module.record_honeypot_hit(_IN_B, 22, "ssh")  # 1 ip, 1 hit = 16
    db_module.record_honeypot_hit(_IN_B, 22, "ssh")  # mesmo ip, +1 hit = 17
    db_module.record_blocked_ip(_IN_C, "teste")      # 1 bloqueado = 5
    risk = client_risk.compute_client_risk("xfiber-teste")
    # 10 + (1*15 + 2*1) + 5 = 32
    assert risk["score"] == 32
    assert risk["tier"] == "alto"


# ---- adjusted_z_threshold ----

def test_adjusted_z_unknown_client_uses_base():
    assert client_risk.adjusted_z_threshold("nao-existe") == client_baseline.DEFAULT_Z_THRESHOLD


def test_adjusted_z_baixo_unchanged():
    _register()
    z = client_risk.adjusted_z_threshold("xfiber-teste")
    assert z == client_baseline.DEFAULT_Z_THRESHOLD


def test_adjusted_z_medio_more_sensitive():
    _register()
    db_module.record_threat_flag(_IN_A)  # score 2 => médio
    z = client_risk.adjusted_z_threshold("xfiber-teste")
    # 3.0 - 0.5 = 2.5
    assert z == 2.5
    assert z < client_baseline.DEFAULT_Z_THRESHOLD


def test_adjusted_z_alto_more_sensitive():
    _register()
    for _ in range(6):
        db_module.record_honeypot_hit(_IN_A, 22, "ssh")  # 1 ip, 6 hits = 21 => alto
    z = client_risk.adjusted_z_threshold("xfiber-teste")
    # 3.0 - 1.0 = 2.0
    assert z == 2.0


def test_adjusted_z_respects_floor():
    _register()
    db_module.record_honeypot_hit(_IN_A, 22, "ssh")  # alto
    # base baixa o suficiente para encostar no piso: 2.0 - 1.0 = 1.0 < 1.5
    z = client_risk.adjusted_z_threshold("xfiber-teste", base=2.0)
    assert z == client_risk._Z_FLOOR


# ---- relatórios textuais ----

def test_describe_unknown_client():
    out = client_risk.describe_client_risk("nao-existe")
    assert "não encontrado" in out.lower()


def test_describe_includes_tier_and_threshold():
    _register()
    for _ in range(6):
        db_module.record_honeypot_hit(_IN_A, 22, "ssh")  # 1 ip, 6 hits = 21 => alto
    out = client_risk.describe_client_risk("xfiber-teste")
    assert "ALTO" in out
    assert "xfiber-teste" in out
    assert "agressivo" in out.lower()


def test_rank_empty():
    out = client_risk.rank_clients_by_risk()
    assert "nenhum" in out.lower()


def test_rank_orders_descending():
    client_baseline.add_client_profile("baixo-risco", "203.0.113.0/24", "")
    client_baseline.add_client_profile("alto-risco", "198.18.0.0/24", "")
    # alto-risco recebe honeypot pesado
    for _ in range(3):
        db_module.record_honeypot_hit("198.18.0.5", 22, "ssh")
    out = client_risk.rank_clients_by_risk()
    pos_alto = out.find("alto-risco")
    pos_baixo = out.find("baixo-risco")
    assert pos_alto != -1 and pos_baixo != -1
    assert pos_alto < pos_baixo  # maior risco aparece primeiro
