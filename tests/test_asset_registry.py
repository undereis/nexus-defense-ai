"""Inventário de ativos autorizados (Prioridade 3) — tools/asset_registry.py.

Cobre classificação de IP, travas de segurança duras (loopback/reservado/infra
própria crítica), modo permissivo vs. estrito e match por CIDR/escopo/validade.
"""

import pytest

import config
import database.db as db_module
from tools import asset_registry, infrastructure


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "test.db")
    db_module.init_db()
    # padrão permissivo, salvo onde o teste sobrescreve
    monkeypatch.setattr(config, "REQUIRE_ASSET_AUTHORIZATION", False, raising=False)
    yield


def test_classify_ip():
    assert asset_registry.classify_ip("127.0.0.1") == "loopback"
    assert asset_registry.classify_ip("10.0.0.5") == "private"
    assert asset_registry.classify_ip("192.168.1.1") == "private"
    assert asset_registry.classify_ip("8.8.8.8") == "public"
    assert asset_registry.classify_ip("224.0.0.1") == "reserved"
    assert asset_registry.classify_ip("não-ip") == "not_ip"


def test_loopback_and_reserved_hard_denied():
    assert asset_registry.check_target("127.0.0.1", "block_ip").hard_denied
    assert asset_registry.check_target("224.0.0.1", "block_ip").hard_denied


def test_loopback_ok_for_read_only_action():
    # changes_state=False não dispara as travas duras (é leitura).
    tc = asset_registry.check_target("127.0.0.1", "status", changes_state=False)
    assert not tc.hard_denied and tc.authorized


def test_public_permissive_allowed_but_unmatched():
    tc = asset_registry.check_target("8.8.8.8", "block_ip")
    assert tc.authorized and not tc.matched and not tc.hard_denied


def test_strict_mode_denies_unregistered(monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_ASSET_AUTHORIZATION", True, raising=False)
    tc = asset_registry.check_target("8.8.8.8", "block_ip")
    assert not tc.authorized and not tc.hard_denied


def test_registered_cidr_and_scope(monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_ASSET_AUTHORIZATION", True, raising=False)
    asset_registry.authorize_asset(
        "lab-net", "lab", cidr="10.10.0.0/24", environment="lab", authorized_scope="block_ip",
    )
    ok = asset_registry.check_target("10.10.0.5", "block_ip")
    assert ok.authorized and ok.matched and ok.asset_id == "lab-net"
    # ação fora do escopo do ativo → negada (modo estrito, sem outro match)
    out_of_scope = asset_registry.check_target("10.10.0.5", "run_exploit")
    assert not out_of_scope.authorized


def test_critical_infra_is_hard_denied():
    infrastructure.register_ip_block("203.0.113.0/24", "core", is_critical=True)
    tc = asset_registry.check_target("203.0.113.10", "block_ip")
    assert tc.hard_denied and not tc.authorized


def test_disabled_asset_does_not_match(monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_ASSET_AUTHORIZATION", True, raising=False)
    asset_registry.authorize_asset("h1", "host", ip="8.8.8.8", authorized_scope="*")
    assert asset_registry.check_target("8.8.8.8", "block_ip").authorized
    asset_registry.set_enabled("h1", False)
    assert not asset_registry.check_target("8.8.8.8", "block_ip").authorized
