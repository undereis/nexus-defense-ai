"""Testes para tools/deception.py — deception ativa (Fase 6, item 4).

Semeio honeynet (espaço morto) + infraestrutura própria no DB temp e mocko
só o seam de DPI (dpi.get_alert_entries), object-form. Verifica sobretudo o
GATE de segurança: um decoy nunca pode cair em infra real/crítica nem fora de
honeynet.
"""

import json

import database.db as db
import pytest

from tools import deception, dpi, honeynet, infrastructure


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    yield


def _declare_honeynet(cidr="10.50.0.0/28"):
    honeynet.declare_range(cidr, "segmento morto de teste")


# ---------- geração pura ----------

def test_generate_decoy_spec():
    spec = deception.generate_decoy_spec("database")
    assert spec["profile"] == "database"
    assert spec["os"] == "Ubuntu 16.04 LTS"
    ports = {s["port"] for s in spec["services"]}
    assert {22, 3306, 6379} <= ports
    assert spec["lure_level"] == "alta"


def test_generate_decoy_spec_unknown_profile():
    assert deception.generate_decoy_spec("nao_existe") is None


def test_list_profiles():
    profs = deception.list_profiles()
    assert "database" in profs and "iot_camera" in profs


# ---------- gate de segurança ----------

def test_decoy_refused_on_own_infrastructure():
    infrastructure.register_ip_block("203.0.50.0/24", "infra Xfiber")
    _declare_honeynet()
    out = deception.deploy_decoy_host("database", ip="203.0.50.10")
    assert "Recusado" in out
    assert "infraestrutura própria" in out
    assert db.list_decoy_assets() == []


def test_decoy_refused_outside_honeynet():
    _declare_honeynet("10.50.0.0/28")
    out = deception.deploy_decoy_host("database", ip="192.0.2.5")  # fora da honeynet
    assert "Recusado" in out
    assert "honeynet" in out
    assert db.list_decoy_assets() == []


def test_decoy_refused_invalid_ip():
    _declare_honeynet()
    out = deception.deploy_decoy_host("database", ip="999.999.0.1")
    assert "Recusado" in out


def test_decoy_needs_honeynet_when_no_ip():
    # sem honeynet declarada e sem IP -> não tem espaço morto para alocar
    out = deception.deploy_decoy_host("database")
    assert "Não há honeynet" in out
    assert db.list_decoy_assets() == []


# ---------- deploy feliz ----------

def test_deploy_allocates_ip_in_honeynet():
    _declare_honeynet("10.50.0.0/28")
    out = deception.deploy_decoy_host("backup")
    assert "Host-isca" in out
    rows = db.list_decoy_assets()
    assert len(rows) == 1
    ip = rows[0][2]
    assert honeynet.is_in_honeynet(ip) is not None  # caiu no espaço morto


def test_deploy_explicit_ip_in_honeynet():
    _declare_honeynet("10.50.0.0/28")
    out = deception.deploy_decoy_host("database", ip="10.50.0.5", hostname="srv-db-prod-fake")
    assert "10.50.0.5" in out
    rows = db.list_decoy_assets()
    assert rows[0][1] == "srv-db-prod-fake"
    assert rows[0][2] == "10.50.0.5"


def test_deploy_no_collision_on_same_ip():
    _declare_honeynet("10.50.0.0/28")
    deception.deploy_decoy_host("database", ip="10.50.0.5")
    out = deception.deploy_decoy_host("backup", ip="10.50.0.5")
    assert "Já existe um decoy" in out


def test_auto_allocation_skips_used_ips():
    _declare_honeynet("10.50.0.0/30")  # poucos hosts -> força reuso de espaço
    deception.deploy_decoy_host("database")
    deception.deploy_decoy_host("backup")
    ips = {r[2] for r in db.list_decoy_assets()}
    assert len(ips) == 2  # alocou dois IPs distintos, sem colidir


# ---------- mapa falso ----------

def test_generate_deception_map():
    _declare_honeynet("10.50.0.0/28")
    deception.deploy_decoy_host("database", ip="10.50.0.5", hostname="srv-db-prod-x")
    doc = deception.generate_deception_map()
    assert "srv-db-prod-x" in doc
    assert "10.50.0.5" in doc
    assert "CONFIDENCIAL" in doc
    assert "vsFTPd" not in doc  # só o perfil database; ftp não entra aqui


def test_generate_deception_map_empty():
    assert "Nenhum decoy" in deception.generate_deception_map()


def test_describe_deception_empty():
    assert "Nenhum host-isca" in deception.describe_deception()


def test_describe_deception_lists_decoys():
    _declare_honeynet("10.50.0.0/28")
    deception.deploy_decoy_host("database", ip="10.50.0.5", hostname="srv-db-prod-x")
    out = deception.describe_deception()
    assert "srv-db-prod-x" in out
    assert "ainda não tocado" in out


# ---------- detecção de consumo ----------

def test_detect_consumption(monkeypatch):
    _declare_honeynet("10.50.0.0/28")
    deception.deploy_decoy_host("database", ip="10.50.0.5", hostname="srv-db-prod-x")
    monkeypatch.setattr(dpi, "get_alert_entries", lambda: [
        {"src_ip": "9.9.9.9", "dest_ip": "10.50.0.5"},  # tocou o decoy
        {"src_ip": "9.9.9.9", "dest_ip": "8.8.8.8"},    # destino legítimo, ignora
    ])
    hits = deception.detect_deception_consumption()
    assert hits == [("9.9.9.9", "10.50.0.5", "srv-db-prod-x")]
    # consumo registrado no decoy
    row = db.list_decoy_assets()[0]
    assert row[8] == 1  # consumed_count


def test_detect_consumption_dedup(monkeypatch):
    _declare_honeynet("10.50.0.0/28")
    deception.deploy_decoy_host("database", ip="10.50.0.5")
    monkeypatch.setattr(dpi, "get_alert_entries", lambda: [
        {"src_ip": "9.9.9.9", "dest_ip": "10.50.0.5"},
        {"src_ip": "9.9.9.9", "dest_ip": "10.50.0.5"},  # mesmo par, conta 1x
    ])
    hits = deception.detect_deception_consumption()
    assert len(hits) == 1


def test_describe_consumption_none(monkeypatch):
    _declare_honeynet("10.50.0.0/28")
    deception.deploy_decoy_host("database", ip="10.50.0.5")
    monkeypatch.setattr(dpi, "get_alert_entries", lambda: [])
    out = deception.describe_deception_consumption()
    assert "Nenhum consumo" in out


def test_describe_consumption_hit(monkeypatch):
    _declare_honeynet("10.50.0.0/28")
    deception.deploy_decoy_host("database", ip="10.50.0.5", hostname="srv-db-prod-x")
    monkeypatch.setattr(dpi, "get_alert_entries", lambda: [
        {"src_ip": "9.9.9.9", "dest_ip": "10.50.0.5"},
    ])
    out = deception.describe_deception_consumption()
    assert "9.9.9.9" in out
    assert "srv-db-prod-x" in out


# ---------- remoção ----------

def test_remove_decoy():
    _declare_honeynet("10.50.0.0/28")
    deception.deploy_decoy_host("database", ip="10.50.0.5")
    decoy_id = db.list_decoy_assets()[0][0]
    assert "removido" in deception.remove_decoy(decoy_id)
    assert db.list_decoy_assets() == []


def test_remove_decoy_unknown():
    assert "Nenhum decoy" in deception.remove_decoy("deadbeef")
