"""Testes para tools/fingerprint.py — fingerprint comportamental de
atacante via sequência de portas + timing. Banco isolado em tmp_path,
dados reais (sem mock de lógica de comparação)."""

import importlib
import time

import pytest


@pytest.fixture
def fp_module(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_fingerprint.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    import tools.fingerprint as fingerprint
    importlib.reload(fingerprint)
    yield fingerprint, dbmod


def _record_sequence(dbmod, ip, ports_services, delay=0.0):
    for port, service in ports_services:
        dbmod.record_honeypot_hit(ip, port, service)
        if delay:
            time.sleep(delay)


def test_compute_fingerprint_empty_ip(fp_module):
    fingerprint, _ = fp_module
    fp = fingerprint.compute_fingerprint("203.0.113.1")
    assert fp["total_hits"] == 0
    assert fp["port_sequence"] == []


def test_compute_fingerprint_with_hits(fp_module):
    fingerprint, dbmod = fp_module
    _record_sequence(dbmod, "203.0.113.1", [(2222, "ssh"), (2121, "ftp"), (8081, "http")])
    fp = fingerprint.compute_fingerprint("203.0.113.1")
    assert fp["total_hits"] == 3
    assert fp["port_sequence"] == [2222, 2121, 8081]


def test_port_sequence_similarity_identical():
    from tools.fingerprint import _port_sequence_similarity
    assert _port_sequence_similarity([22, 21, 80], [22, 21, 80]) == 1.0


def test_port_sequence_similarity_no_overlap():
    from tools.fingerprint import _port_sequence_similarity
    assert _port_sequence_similarity([22, 21, 80], [443, 3306, 9999]) == 0.0


def test_port_sequence_similarity_empty():
    from tools.fingerprint import _port_sequence_similarity
    assert _port_sequence_similarity([], [22]) == 0.0


def test_find_similar_attackers_below_min_hits_returns_empty(fp_module):
    fingerprint, dbmod = fp_module
    _record_sequence(dbmod, "203.0.113.1", [(2222, "ssh")])
    matches = fingerprint.find_similar_attackers("203.0.113.1")
    assert matches == []


def test_find_similar_attackers_detects_same_pattern_different_ip(fp_module):
    """Sem sleep entre hits: ambos os IPs gravam timestamps no mesmo
    segundo, então os intervalos batem de forma determinística (sem
    depender de qual lado da fronteira do segundo o sleep cai —
    honeypot_hits só tem resolução de 1s, ver aviso no módulo)."""
    fingerprint, dbmod = fp_module
    sequence = [(2222, "ssh"), (2121, "ftp"), (8081, "http")]
    _record_sequence(dbmod, "198.51.100.10", sequence)
    _record_sequence(dbmod, "198.51.100.20", sequence)

    matches = fingerprint.find_similar_attackers("198.51.100.10")
    assert len(matches) == 1
    assert matches[0][0] == "198.51.100.20"
    assert matches[0][1] >= fingerprint.DEFAULT_SIMILARITY_THRESHOLD


def test_find_similar_attackers_no_match_for_different_pattern(fp_module):
    fingerprint, dbmod = fp_module
    _record_sequence(dbmod, "198.51.100.10", [(2222, "ssh"), (2121, "ftp"), (8081, "http")])
    _record_sequence(dbmod, "198.51.100.30", [(443, "http"), (3306, "http"), (9999, "http")])

    matches = fingerprint.find_similar_attackers("198.51.100.10")
    assert matches == []


def test_describe_similar_attackers_insufficient_data(fp_module):
    fingerprint, dbmod = fp_module
    _record_sequence(dbmod, "203.0.113.1", [(2222, "ssh")])
    result = fingerprint.describe_similar_attackers("203.0.113.1")
    assert "não confiável" in result


def test_describe_similar_attackers_with_match(fp_module):
    fingerprint, dbmod = fp_module
    sequence = [(2222, "ssh"), (2121, "ftp"), (8081, "http")]
    _record_sequence(dbmod, "198.51.100.10", sequence)
    _record_sequence(dbmod, "198.51.100.20", sequence)

    result = fingerprint.describe_similar_attackers("198.51.100.10")
    assert "198.51.100.20" in result
    assert "similaridade" in result
