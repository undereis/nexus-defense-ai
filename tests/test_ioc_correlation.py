"""Testes para tools/ioc_correlation.py — correlação automática de
IOCs (recon detectado -> escalado para reincidente conhecido)."""

import importlib
import json

import pytest


@pytest.fixture
def ioc_module(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_ioc.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    monkeypatch.setattr(config, "DPI_LOG_DIR", tmp_path)
    import tools.dpi as dpi
    importlib.reload(dpi)

    import tools.threat_intel as threat_intel
    importlib.reload(threat_intel)

    import tools.ioc_correlation as ioc
    importlib.reload(ioc)
    yield ioc, dbmod, dpi, threat_intel


def _write_eve_json(dpi_module, entries):
    eve_path = dpi_module.DPI_LOG_DIR / "eve.json"
    with eve_path.open("w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


def test_has_recon_signal_false_for_clean_ip(ioc_module):
    ioc, _, _, _ = ioc_module
    assert ioc.has_recon_signal("203.0.113.1") is False


def test_has_recon_signal_true_for_honeypot_hit(ioc_module):
    ioc, dbmod, _, _ = ioc_module
    dbmod.record_honeypot_hit("203.0.113.2", 2222, "ssh")
    assert ioc.has_recon_signal("203.0.113.2") is True


def test_has_recon_signal_true_for_dpi_scan_alert(ioc_module):
    ioc, _, dpi, _ = ioc_module
    _write_eve_json(dpi, [
        {"event_type": "alert", "src_ip": "203.0.113.3",
         "alert": {"signature": "ET SCAN Nmap Scripting Engine", "category": "Attempted Recon"}},
    ])
    assert ioc.has_recon_signal("203.0.113.3") is True


def test_has_recon_signal_false_for_non_recon_dpi_alert(ioc_module):
    ioc, _, dpi, _ = ioc_module
    _write_eve_json(dpi, [
        {"event_type": "alert", "src_ip": "203.0.113.4",
         "alert": {"signature": "ET MALWARE Generic Trojan", "category": "Malware"}},
    ])
    assert ioc.has_recon_signal("203.0.113.4") is False


def test_get_recon_ips_from_dpi_ignores_non_alert_events(ioc_module):
    ioc, _, dpi, _ = ioc_module
    _write_eve_json(dpi, [
        {"event_type": "flow", "src_ip": "203.0.113.5"},
        {"event_type": "alert", "src_ip": "203.0.113.6",
         "alert": {"signature": "ET SCAN", "category": "Attempted Recon"}},
    ])
    ips = ioc.get_recon_ips_from_dpi()
    assert ips == {"203.0.113.6"}


def test_correlate_and_escalate_no_signal_returns_none(ioc_module):
    ioc, _, _, _ = ioc_module
    assert ioc.correlate_and_escalate("203.0.113.7") is None


def test_correlate_and_escalate_escalates_new_ip_to_repeat_offender(ioc_module):
    ioc, dbmod, _, threat_intel = ioc_module
    dbmod.record_honeypot_hit("203.0.113.8", 2222, "ssh")

    assert threat_intel.is_repeat_offender("203.0.113.8") is False

    result = ioc.correlate_and_escalate("203.0.113.8")
    assert result is not None
    assert "escalado" in result

    assert threat_intel.is_repeat_offender("203.0.113.8") is True


def test_correlate_and_escalate_is_idempotent(ioc_module):
    ioc, dbmod, _, _ = ioc_module
    dbmod.record_honeypot_hit("203.0.113.9", 2222, "ssh")

    first = ioc.correlate_and_escalate("203.0.113.9")
    second = ioc.correlate_and_escalate("203.0.113.9")

    assert first is not None
    assert second is None  # já era reincidente, não escala de novo


def test_describe_recon_watchlist_empty(ioc_module):
    ioc, _, _, _ = ioc_module
    assert "Nenhum IP" in ioc.describe_recon_watchlist()


def test_describe_recon_watchlist_with_entries(ioc_module):
    ioc, _, dpi, _ = ioc_module
    _write_eve_json(dpi, [
        {"event_type": "alert", "src_ip": "203.0.113.6",
         "alert": {"signature": "ET SCAN", "category": "Attempted Recon"}},
    ])
    result = ioc.describe_recon_watchlist()
    assert "203.0.113.6" in result
