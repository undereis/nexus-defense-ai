import importlib

import pytest


@pytest.fixture
def report_module(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_report.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    import tools.report as report
    importlib.reload(report)
    monkeypatch.setattr(report, "list_blocked", lambda: "Nenhum IP bloqueado atualmente.")
    yield report, dbmod


def test_no_events_in_period(report_module):
    report, _ = report_module
    result = report.generate_summary_report(24)
    assert "Nenhum evento registrado" in result
    assert "últimas 24h" in result


def test_counts_total_events(report_module):
    report, dbmod = report_module
    dbmod.log_event("a", "1.1.1.1", "x", "")
    dbmod.log_event("b", "2.2.2.2", "y", "")
    dbmod.log_event("a", "3.3.3.3", "z", "")

    result = report.generate_summary_report(24)
    assert "Total de eventos: 3" in result
    assert "a: 2" in result
    assert "b: 1" in result


def test_highlights_known_event_types(report_module):
    report, dbmod = report_module
    dbmod.log_event("ddos_severe", "1.1.1.1", "auto-isolado", "")
    dbmod.log_event("honeypot_hit", "2.2.2.2", "ssh", "")
    dbmod.log_event("honeypot_credential_captured", "2.2.2.2", "ftp", "")

    result = report.generate_summary_report(24)
    assert "Ataques DDoS auto-isolados: 1" in result
    assert "Capturas em honeypot: 1" in result
    assert "Credenciais capturadas em honeypot: 1" in result


def test_no_highlights_when_only_unknown_event_types(report_module):
    report, dbmod = report_module
    dbmod.log_event("algum_evento_qualquer", None, "x", "")

    result = report.generate_summary_report(24)
    assert "Nenhum destaque relevante" in result


def test_includes_current_firewall_state(report_module, monkeypatch):
    report, dbmod = report_module
    monkeypatch.setattr(report, "list_blocked", lambda: "1.2.3.4\n5.6.7.8")

    result = report.generate_summary_report(24)
    assert "Estado atual do firewall:" in result
    assert "1.2.3.4" in result
    assert "5.6.7.8" in result


def test_respects_custom_hours_window(report_module):
    report, dbmod = report_module
    result = report.generate_summary_report(1.5)
    assert "últimas 1.5h" in result
