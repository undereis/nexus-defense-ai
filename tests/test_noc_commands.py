"""Testes do fast-path de comandos do NOC (Fase 8, Frente E)."""

import pytest

import database.db as db_module
from tools import noc_commands


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    db_module.init_db()
    yield


def _seed():
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="pendente", days_overdue=9)
    db_module.add_subscriber("c2", "203.0.113.6")
    db_module.set_subscriber_status("c1", "bloqueado_inadimplencia")
    db_module.add_monitored_device("d1", "10.0.0.1", name="OLT-1")
    db_module.set_device_status("d1", "offline")
    db_module.open_device_outage("d1", "10.0.0.1", "OLT-1", "Sem resposta ao ping")


def test_help_recognized():
    out = noc_commands.handle_command("help")
    assert out and "/status" in out


def test_status_returns_panel():
    _seed()
    out = noc_commands.handle_command("status")
    assert "PAINEL NOC" in out


def test_devices():
    _seed()
    out = noc_commands.handle_command("devices")
    assert "OLT-1" in out and "🔴" in out


def test_outages():
    _seed()
    out = noc_commands.handle_command("outages")
    assert "OLT-1" in out


def test_subscribers():
    _seed()
    out = noc_commands.handle_command("subscribers")
    assert "Assinantes: 2" in out


def test_delinquent():
    _seed()
    # c1 está bloqueado, então não conta como inadimplente "ativo"; adiciona um ativo
    db_module.add_subscriber("c3", "203.0.113.7", invoice_status="pendente", days_overdue=10)
    out = noc_commands.handle_command("delinquent")
    assert "c3" in out


def test_synonyms_and_slash_and_case():
    _seed()
    assert "PAINEL NOC" in noc_commands.handle_command("/STATUS")
    assert "PAINEL NOC" in noc_commands.handle_command("painel")
    assert noc_commands.handle_command("/equipamentos").startswith("*Equipamentos")


def test_unknown_returns_none():
    # linguagem natural e ações NÃO são fast-path -> caem no agente
    assert noc_commands.handle_command("qual o status da rede hoje?") is None
    assert noc_commands.handle_command("bloqueia o cliente c1") is None
    assert noc_commands.handle_command("block c1") is None
    assert noc_commands.handle_command("") is None
