import importlib

import pytest


@pytest.fixture
def dossier_module(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_dossier.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    import tools.dossier as dossier
    importlib.reload(dossier)
    monkeypatch.setattr(dossier.geoip, "describe_location", lambda ip: f"{ip}: localização de teste")
    yield dossier, dbmod


def test_dossier_for_unknown_ip_has_no_signals(dossier_module):
    dossier, _ = dossier_module
    result = dossier.build_dossier("1.2.3.4")
    assert "1.2.3.4" in result
    assert "Sem sinais fortes de ameaça" in result
    assert "Nenhum registro de ataque" in result
    assert "Nenhuma conexão em honeypot" in result
    assert "Nenhuma credencial capturada" in result
    assert "Nenhuma auditoria" in result


def test_dossier_aggregates_threat_intel(dossier_module):
    dossier, dbmod = dossier_module
    dbmod.record_threat_isolation("9.9.9.9")
    dbmod.record_threat_isolation("9.9.9.9")

    result = dossier.build_dossier("9.9.9.9")
    assert "Isolado: 2x" in result
    assert "REINCIDENTE CONHECIDO" in result
    assert "AMEAÇA CONFIRMADA" in result


def test_dossier_aggregates_honeypot_hits_and_credentials(dossier_module):
    dossier, dbmod = dossier_module
    dbmod.record_honeypot_hit("8.8.4.4", 2121, "ftp")
    dbmod.record_honeypot_credential("8.8.4.4", 2121, "ftp", "admin", "1234")

    result = dossier.build_dossier("8.8.4.4")
    assert "Capturas em honeypot (1)" in result
    assert "Credenciais capturadas (1)" in result
    assert "valores protegidos" in result
    assert "admin" not in result
    assert "1234" not in result
    assert "credential stuffing" in result.lower()


def test_dossier_aggregates_scan_findings(dossier_module):
    dossier, dbmod = dossier_module
    dbmod.record_finding("5.5.5.5", "nmap", "porta 22 aberta")

    result = dossier.build_dossier("5.5.5.5")
    assert "Auditorias de segurança prévias neste IP (1)" in result
    assert "porta 22 aberta" in result
    assert "AMEAÇA CONFIRMADA" in result


def test_dossier_combines_multiple_sources(dossier_module):
    dossier, dbmod = dossier_module
    dbmod.record_threat_isolation("3.3.3.3")
    dbmod.record_honeypot_hit("3.3.3.3", 2222, "ssh")
    dbmod.record_finding("3.3.3.3", "nikto", "vulnerabilidade x")

    result = dossier.build_dossier("3.3.3.3")
    assert "AMEAÇA CONFIRMADA" in result
    assert "reincidente em ataques de rede" in result
    assert "capturado em 1 honeypot" in result
    assert "correlacione vulnerabilidades" in result
