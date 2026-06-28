"""Testes para tools/infrastructure.py — mapa de infraestrutura própria."""

import pytest

from tools import infrastructure


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    """Banco isolado por teste."""
    import database.db as db_module
    from pathlib import Path
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    db_module.init_db()
    yield


def test_register_ip_block_returns_success():
    result = infrastructure.register_ip_block("10.0.0.0/24", "Bloco test")
    assert "10.0.0.0/24" in result


def test_register_ip_block_critical_flag():
    result = infrastructure.register_ip_block("10.0.0.0/24", "DNS", is_critical=True)
    assert "CRÍTICO" in result


def test_invalid_cidr_rejected():
    result = infrastructure.register_ip_block("999.999.0.0/24", "inválido")
    assert "inválido" in result.lower() or "CIDR" in result


def test_cidr_is_normalized():
    # 10.0.0.5/24 deve ser normalizado para 10.0.0.0/24
    infrastructure.register_ip_block("10.0.0.5/24", "host bit set")
    result = infrastructure.list_own_infrastructure()
    assert "10.0.0.0/24" in result


def test_list_infrastructure_empty():
    result = infrastructure.list_own_infrastructure()
    assert "vazia" in result.lower() or "nenhum" in result.lower()


def test_list_infrastructure_shows_block():
    infrastructure.register_ip_block("192.168.1.0/24", "LAN interna")
    result = infrastructure.list_own_infrastructure()
    assert "192.168.1.0/24" in result
    assert "LAN interna" in result


def test_unregister_ip_block():
    infrastructure.register_ip_block("172.16.0.0/12", "test")
    infrastructure.unregister_ip_block("172.16.0.0/12")
    result = infrastructure.list_own_infrastructure()
    assert "172.16.0.0/12" not in result


def test_is_own_ip_true():
    infrastructure.register_ip_block("10.10.0.0/16", "bloco")
    assert infrastructure.is_own_ip("10.10.5.1") is True


def test_is_own_ip_false_outside():
    infrastructure.register_ip_block("10.10.0.0/16", "bloco")
    assert infrastructure.is_own_ip("192.168.1.1") is False


def test_is_own_ip_empty_map():
    assert infrastructure.is_own_ip("1.2.3.4") is False


def test_is_critical_ip_true():
    infrastructure.register_ip_block("10.0.0.0/24", "DNS", is_critical=True)
    assert infrastructure.is_critical_ip("10.0.0.1") is True


def test_is_critical_ip_non_critical_block():
    infrastructure.register_ip_block("10.0.1.0/24", "não crítico", is_critical=False)
    assert infrastructure.is_critical_ip("10.0.1.5") is False


def test_register_own_asn_normalizes():
    result = infrastructure.register_own_asn("65001", "ASN Xfiber")
    assert "AS65001" in result


def test_register_own_asn_with_prefix():
    result = infrastructure.register_own_asn("AS65002", "ASN secundário")
    assert "AS65002" in result


def test_asn_shows_in_infrastructure_list():
    infrastructure.register_own_asn("AS65001", "ASN principal")
    result = infrastructure.list_own_infrastructure()
    assert "AS65001" in result


def test_register_topology_node():
    result = infrastructure.register_topology_node(
        "rb750-core", "router", "192.168.0.1", "Mikrotik principal"
    )
    assert "rb750-core" in result


def test_topology_node_shows_in_list():
    infrastructure.register_topology_node("dns1", "dns", "10.0.0.90", "DNS primário")
    result = infrastructure.list_own_infrastructure()
    assert "dns1" in result
    assert "10.0.0.90" in result


def test_unregister_topology_node():
    infrastructure.register_topology_node("temp-node", "server", "10.0.0.5")
    infrastructure.unregister_topology_node("temp-node")
    result = infrastructure.list_own_infrastructure()
    assert "temp-node" not in result
