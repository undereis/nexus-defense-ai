"""Testes do autodiagnóstico de prontidão (Frente F — tools/selftest.py)."""

import pytest

import database.db as db_module
from tools import noc_commands, selftest


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    db_module.init_db()
    yield


def test_runs_with_all_sections_on_empty_db():
    out = selftest.run_selftest()
    for marker in ("AUTODIAGNÓSTICO", "Núcleo", "DB acessível",
                   "Auditoria íntegra", "Integrações", "Travas de segurança",
                   "Operação NOC", "Defesa ativa"):
        assert marker in out


def test_reflects_noc_state():
    db_module.add_subscriber("c1", "203.0.113.5")
    db_module.set_subscriber_status("c1", "bloqueado_inadimplencia")
    db_module.add_monitored_device("d1", "10.0.0.1")
    db_module.set_device_status("d1", "offline")
    db_module.open_device_outage("d1", "10.0.0.1", "OLT", "ping")

    out = selftest.run_selftest()
    assert "Assinantes: 1 (1 bloqueados)" in out
    assert "1 offline" in out
    assert "Quedas abertas: 1" in out


def test_audit_intact_reported():
    db_module.log_event("teste", None, "evento de teste")
    out = selftest.run_selftest()
    assert "Auditoria íntegra" in out


def test_never_crashes_even_if_a_check_fails(monkeypatch):
    # força uma exceção numa sub-checagem e garante que o relatório ainda sai
    monkeypatch.setattr(selftest, "list_subscribers", lambda *a, **k: 1 / 0)
    out = selftest.run_selftest()
    assert "AUTODIAGNÓSTICO" in out  # não propagou a exceção


def test_health_via_noc_fast_path():
    assert "AUTODIAGNÓSTICO" in noc_commands.handle_command("health")
    assert noc_commands.handle_command("/saude") is not None
    assert noc_commands.handle_command("diagnostico") is not None
