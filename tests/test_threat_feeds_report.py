"""Testes para o reporte automático ao AbuseIPDB (tools/threat_feeds.py
report_to_abuseipdb + categorize_isolation_reason, e o gancho único em
tools/threat_intel.record_confirmed_isolation)."""

import importlib

import pytest

from tools import threat_feeds


def test_categorize_ddos_reason():
    categories = threat_feeds.categorize_isolation_reason("Auto-isolado: conexões 50x acima do normal")
    assert threat_feeds.ABUSEIPDB_CATEGORY_DDOS in categories
    assert threat_feeds.ABUSEIPDB_CATEGORY_HACKING in categories


def test_categorize_honeypot_ftp_reason():
    categories = threat_feeds.categorize_isolation_reason("Honeypot (ftp): conectou na porta-armadilha 2121")
    assert threat_feeds.ABUSEIPDB_CATEGORY_BRUTE_FORCE in categories


def test_categorize_scan_reason():
    categories = threat_feeds.categorize_isolation_reason("IP em feed(s) de threat intel conhecido")
    assert threat_feeds.ABUSEIPDB_CATEGORY_PORT_SCAN in categories


def test_categorize_always_includes_hacking_fallback():
    categories = threat_feeds.categorize_isolation_reason("motivo genérico sem palavra-chave")
    assert categories == [threat_feeds.ABUSEIPDB_CATEGORY_HACKING]


def test_report_to_abuseipdb_not_configured(monkeypatch):
    monkeypatch.setattr(threat_feeds, "ABUSEIPDB_API_KEY", "")
    result = threat_feeds.report_to_abuseipdb("1.2.3.4", [15], "teste")
    assert "não configurado" in result
    assert "não enviado" in result


def test_report_to_abuseipdb_sends_correct_payload(monkeypatch):
    monkeypatch.setattr(threat_feeds, "ABUSEIPDB_API_KEY", "fake-key")
    captured = {}

    class FakeResp:
        def json(self):
            return {"data": {"abuseConfidenceScore": 77}}

    def fake_post(url, headers=None, data=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["data"] = data
        return FakeResp()

    monkeypatch.setattr(threat_feeds.requests, "post", fake_post)

    result = threat_feeds.report_to_abuseipdb("1.2.3.4", [4, 15], "ataque ddos confirmado")

    assert captured["url"] == "https://api.abuseipdb.com/api/v2/report"
    assert captured["data"]["ip"] == "1.2.3.4"
    assert captured["data"]["categories"] == "4,15"
    assert "77" in result


def test_report_to_abuseipdb_handles_api_error(monkeypatch):
    monkeypatch.setattr(threat_feeds, "ABUSEIPDB_API_KEY", "fake-key")

    class FakeResp:
        def json(self):
            return {"errors": [{"detail": "Invalid IP"}]}

    monkeypatch.setattr(threat_feeds.requests, "post", lambda *a, **k: FakeResp())

    result = threat_feeds.report_to_abuseipdb("not-an-ip", [15], "teste")
    assert "rejeitou" in result


def test_report_to_abuseipdb_network_failure_does_not_raise(monkeypatch):
    monkeypatch.setattr(threat_feeds, "ABUSEIPDB_API_KEY", "fake-key")

    import requests
    def raise_error(*a, **k):
        raise requests.RequestException("boom")
    monkeypatch.setattr(threat_feeds.requests, "post", raise_error)

    result = threat_feeds.report_to_abuseipdb("1.2.3.4", [15], "teste")
    assert "Falha ao reportar" in result


@pytest.fixture
def threat_intel_module(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_ti.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    monkeypatch.setattr(config, "AUTO_REPORT_ABUSEIPDB", True)
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "")
    import tools.threat_intel as threat_intel
    importlib.reload(threat_intel)
    yield threat_intel, dbmod


def test_record_confirmed_isolation_records_locally_even_without_api_key(threat_intel_module):
    threat_intel, dbmod = threat_intel_module
    threat_intel.record_confirmed_isolation("1.2.3.4", "teste")

    history = dbmod.get_threat_history("1.2.3.4")
    assert history is not None
    assert history[3] == 1  # times_isolated


def test_record_confirmed_isolation_skips_report_when_auto_report_disabled(threat_intel_module, monkeypatch):
    threat_intel, dbmod = threat_intel_module
    monkeypatch.setattr(threat_intel, "AUTO_REPORT_ABUSEIPDB", False)

    calls = []
    monkeypatch.setattr(
        "tools.threat_feeds.report_to_abuseipdb",
        lambda *a, **k: calls.append(a) or "não deveria rodar",
    )

    threat_intel.record_confirmed_isolation("1.2.3.4", "teste")
    assert calls == []


def test_record_confirmed_isolation_never_raises_on_report_failure(threat_intel_module, monkeypatch):
    threat_intel, dbmod = threat_intel_module

    def raise_error(*a, **k):
        raise RuntimeError("falha simulada no report")

    monkeypatch.setattr("tools.threat_feeds.categorize_isolation_reason", raise_error)

    # Não deve levantar exceção mesmo com a categorização falhando.
    threat_intel.record_confirmed_isolation("1.2.3.4", "teste")
    history = dbmod.get_threat_history("1.2.3.4")
    assert history[3] == 1
