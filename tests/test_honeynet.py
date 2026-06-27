"""Testes para tools/honeynet.py — honeynet declarativa + cruzamento
com alertas de DPI. Lógica de IP/CIDR pura, sem dependência de socket
real — não afetada pelo problema de ambiente documentado em
tests/test_honeytokens.py."""

import importlib
import json

import pytest


@pytest.fixture
def honeynet_module(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_honeynet.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    monkeypatch.setattr(config, "DPI_LOG_DIR", tmp_path)
    import tools.dpi as dpi
    importlib.reload(dpi)

    import tools.honeynet as honeynet
    importlib.reload(honeynet)
    yield honeynet, dpi, dbmod


def _write_eve_json(dpi_module, entries):
    eve_path = dpi_module.DPI_LOG_DIR / "eve.json"
    with eve_path.open("w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


def test_declare_range_normalizes_cidr(honeynet_module):
    honeynet, _, _ = honeynet_module
    result = honeynet.declare_range("10.250.0.5/28", "teste")
    assert "10.250.0.0/28" in result  # normalizado para o endereço de rede


def test_declare_range_rejects_invalid_cidr(honeynet_module):
    honeynet, _, _ = honeynet_module
    result = honeynet.declare_range("not-a-cidr", "teste")
    assert "inválido" in result


def test_list_ranges_empty(honeynet_module):
    honeynet, _, _ = honeynet_module
    assert "Nenhuma honeynet declarada" in honeynet.list_ranges()


def test_list_ranges_after_declaring(honeynet_module):
    honeynet, _, _ = honeynet_module
    honeynet.declare_range("10.250.0.0/28", "segmento reservado")
    result = honeynet.list_ranges()
    assert "10.250.0.0/28" in result
    assert "segmento reservado" in result


def test_is_in_honeynet_true_for_address_inside_range(honeynet_module):
    honeynet, _, _ = honeynet_module
    honeynet.declare_range("10.250.0.0/28", "segmento reservado")
    assert honeynet.is_in_honeynet("10.250.0.5") == "segmento reservado"


def test_is_in_honeynet_none_for_address_outside_range(honeynet_module):
    honeynet, _, _ = honeynet_module
    honeynet.declare_range("10.250.0.0/28", "segmento reservado")
    assert honeynet.is_in_honeynet("10.250.1.5") is None


def test_is_in_honeynet_handles_invalid_ip_gracefully(honeynet_module):
    honeynet, _, _ = honeynet_module
    honeynet.declare_range("10.250.0.0/28", "segmento reservado")
    assert honeynet.is_in_honeynet("not-an-ip") is None


def test_undeclare_range_removes_it(honeynet_module):
    honeynet, _, _ = honeynet_module
    honeynet.declare_range("10.250.0.0/28", "segmento reservado")
    result = honeynet.undeclare_range("10.250.0.0/28")
    assert "removida" in result
    assert honeynet.is_in_honeynet("10.250.0.5") is None


def test_undeclare_range_unknown_cidr(honeynet_module):
    honeynet, _, _ = honeynet_module
    result = honeynet.undeclare_range("10.250.0.0/28")
    assert "Nenhuma honeynet declarada com o CIDR" in result


def test_describe_honeynet_violations_without_any_declared(honeynet_module):
    honeynet, _, _ = honeynet_module
    result = honeynet.describe_honeynet_violations()
    assert "declare um intervalo" in result


def test_describe_honeynet_violations_with_no_dpi_data(honeynet_module):
    honeynet, _, _ = honeynet_module
    honeynet.declare_range("10.250.0.0/28", "segmento reservado")
    result = honeynet.describe_honeynet_violations()
    assert "Nenhuma violação" in result


def test_check_dpi_traffic_flags_external_source_reaching_honeynet_destination(honeynet_module):
    honeynet, dpi, _ = honeynet_module
    honeynet.declare_range("10.250.0.0/28", "segmento reservado")
    _write_eve_json(dpi, [
        {"event_type": "alert", "src_ip": "203.0.113.99", "dest_ip": "10.250.0.7",
         "alert": {"signature": "x", "category": "y"}},
    ])

    hits = honeynet.check_dpi_traffic_against_honeynet()
    assert hits == [("203.0.113.99", "segmento reservado (alcançou 10.250.0.7)")]


def test_check_dpi_traffic_flags_source_originating_inside_honeynet(honeynet_module):
    honeynet, dpi, _ = honeynet_module
    honeynet.declare_range("10.250.0.0/28", "segmento reservado")
    _write_eve_json(dpi, [
        {"event_type": "alert", "src_ip": "10.250.0.9", "dest_ip": "1.2.3.4",
         "alert": {"signature": "x", "category": "y"}},
    ])

    hits = honeynet.check_dpi_traffic_against_honeynet()
    assert hits == [("10.250.0.9", "segmento reservado (origem dentro do segmento)")]


def test_check_dpi_traffic_ignores_unrelated_traffic(honeynet_module):
    honeynet, dpi, _ = honeynet_module
    honeynet.declare_range("10.250.0.0/28", "segmento reservado")
    _write_eve_json(dpi, [
        {"event_type": "alert", "src_ip": "8.8.8.8", "dest_ip": "10.0.0.5",
         "alert": {"signature": "x", "category": "y"}},
    ])

    assert honeynet.check_dpi_traffic_against_honeynet() == []


def test_check_dpi_traffic_deduplicates_repeated_violator(honeynet_module):
    honeynet, dpi, _ = honeynet_module
    honeynet.declare_range("10.250.0.0/28", "segmento reservado")
    _write_eve_json(dpi, [
        {"event_type": "alert", "src_ip": "203.0.113.99", "dest_ip": "10.250.0.7",
         "alert": {"signature": "a", "category": "y"}},
        {"event_type": "alert", "src_ip": "203.0.113.99", "dest_ip": "10.250.0.8",
         "alert": {"signature": "b", "category": "y"}},
    ])

    hits = honeynet.check_dpi_traffic_against_honeynet()
    assert len(hits) == 1


def test_describe_honeynet_violations_with_real_violation(honeynet_module):
    honeynet, dpi, _ = honeynet_module
    honeynet.declare_range("10.250.0.0/28", "segmento reservado")
    _write_eve_json(dpi, [
        {"event_type": "alert", "src_ip": "203.0.113.99", "dest_ip": "10.250.0.7",
         "alert": {"signature": "x", "category": "y"}},
    ])

    result = honeynet.describe_honeynet_violations()
    assert "VIOLAÇÃO DE HONEYNET" in result
    assert "203.0.113.99" in result
