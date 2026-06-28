"""Testes para tools/asset_inventory.py — inventário automático de ativos."""

import json
import pytest

from tools import asset_inventory, infrastructure


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    import database.db as db_module
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    db_module.init_db()
    yield


def test_scan_no_blocks_registered():
    result = asset_inventory.scan_network()
    assert "Nenhum bloco IP registrado" in result


def test_scan_nmap_not_installed(monkeypatch):
    infrastructure.register_ip_block("10.0.0.0/24", "test")
    monkeypatch.setattr(asset_inventory, "_run_nmap", lambda *a, **kw: "")
    result = asset_inventory.scan_network("10.0.0.0/24")
    assert "nenhum host ativo" in result.lower() or "Scan concluído" in result


def test_scan_detects_new_host(monkeypatch):
    infrastructure.register_ip_block("10.0.0.0/24", "bloco")

    fake_output = (
        "Nmap scan report for 10.0.0.1\n"
        "Host is up (0.001s latency).\n"
        "22/tcp open  ssh\n"
    )
    monkeypatch.setattr(asset_inventory, "_run_nmap", lambda *a, **kw: fake_output)
    result = asset_inventory.scan_network("10.0.0.0/24", mode="light")
    assert "NOVO" in result
    assert "10.0.0.1" in result


def test_scan_detects_changed_ports(monkeypatch):
    infrastructure.register_ip_block("10.0.0.0/24", "bloco")

    first_output = (
        "Nmap scan report for 10.0.0.2\n"
        "Host is up.\n"
        "22/tcp open  ssh\n"
    )
    monkeypatch.setattr(asset_inventory, "_run_nmap", lambda *a, **kw: first_output)
    asset_inventory.scan_network("10.0.0.0/24", mode="light")

    second_output = (
        "Nmap scan report for 10.0.0.2\n"
        "Host is up.\n"
        "22/tcp open  ssh\n"
        "80/tcp open  http\n"
    )
    monkeypatch.setattr(asset_inventory, "_run_nmap", lambda *a, **kw: second_output)
    result = asset_inventory.scan_network("10.0.0.0/24", mode="light")
    assert "MUDANÇA" in result or "Sem mudanças" in result


def test_scan_no_changes_reports_ok(monkeypatch):
    infrastructure.register_ip_block("10.0.0.0/24", "bloco")
    fake_output = (
        "Nmap scan report for 10.0.0.3\n"
        "Host is up.\n"
    )
    monkeypatch.setattr(asset_inventory, "_run_nmap", lambda *a, **kw: fake_output)
    asset_inventory.scan_network("10.0.0.0/24")
    result = asset_inventory.scan_network("10.0.0.0/24")
    assert "Sem mudanças" in result


def test_list_known_assets_empty():
    result = asset_inventory.list_known_assets()
    assert "vazio" in result.lower() or "nenhum" in result.lower()


def test_list_known_assets_shows_ip(monkeypatch):
    infrastructure.register_ip_block("10.0.0.0/24", "bloco")
    fake_output = (
        "Nmap scan report for 10.0.0.5\n"
        "Host is up.\n"
        "443/tcp open  https\n"
    )
    monkeypatch.setattr(asset_inventory, "_run_nmap", lambda *a, **kw: fake_output)
    asset_inventory.scan_network("10.0.0.0/24", mode="light")
    result = asset_inventory.list_known_assets()
    assert "10.0.0.5" in result


def test_list_asset_changes_empty():
    result = asset_inventory.list_asset_changes()
    assert "nenhuma" in result.lower() or "Nenhuma" in result


def test_list_asset_changes_records_port_change(monkeypatch):
    infrastructure.register_ip_block("10.0.0.0/24", "bloco")
    first = (
        "Nmap scan report for 10.0.0.10\n"
        "Host is up.\n"
        "22/tcp open  ssh\n"
    )
    monkeypatch.setattr(asset_inventory, "_run_nmap", lambda *a, **kw: first)
    asset_inventory.scan_network("10.0.0.0/24", mode="light")

    second = (
        "Nmap scan report for 10.0.0.10\n"
        "Host is up.\n"
        "22/tcp open  ssh\n"
        "3306/tcp open  mysql\n"
    )
    monkeypatch.setattr(asset_inventory, "_run_nmap", lambda *a, **kw: second)
    asset_inventory.scan_network("10.0.0.0/24", mode="light")

    changes = asset_inventory.list_asset_changes()
    assert "10.0.0.10" in changes


def test_scan_with_hostname(monkeypatch):
    infrastructure.register_ip_block("10.0.0.0/24", "bloco")
    fake_output = (
        "Nmap scan report for meuservidor.local (10.0.0.20)\n"
        "Host is up.\n"
    )
    monkeypatch.setattr(asset_inventory, "_run_nmap", lambda *a, **kw: fake_output)
    asset_inventory.scan_network("10.0.0.0/24")
    result = asset_inventory.list_known_assets()
    assert "10.0.0.20" in result
