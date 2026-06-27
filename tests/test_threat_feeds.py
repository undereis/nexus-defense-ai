"""Testes para tools/threat_feeds.py — correlação com feeds externos.

Sem chave de API real disponível neste ambiente, então:
- comportamento "não configurado" é testado contra o módulo real (sem
  mock, é literalmente o estado atual do .env de desenvolvimento).
- comportamento com dado real da API é testado via mock de
  requests.get, no nível certo (a chamada de rede, não a função sob
  teste)."""

import importlib

import pytest


@pytest.fixture
def feeds_module(monkeypatch):
    import config
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "")
    monkeypatch.setattr(config, "VIRUSTOTAL_API_KEY", "")
    monkeypatch.setattr(config, "SHODAN_API_KEY", "")
    import tools.threat_feeds as feeds
    importlib.reload(feeds)
    yield feeds
    importlib.reload(feeds)


def test_check_abuseipdb_not_configured(feeds_module):
    result = feeds_module.check_abuseipdb("8.8.8.8")
    assert "não configurado" in result
    assert "ABUSEIPDB_API_KEY" in result


def test_check_virustotal_ip_not_configured(feeds_module):
    result = feeds_module.check_virustotal_ip("8.8.8.8")
    assert "não configurado" in result


def test_check_shodan_not_configured(feeds_module):
    result = feeds_module.check_shodan("8.8.8.8")
    assert "não configurado" in result


def test_correlate_ip_with_nothing_configured_does_not_raise(feeds_module):
    result = feeds_module.correlate_ip("8.8.8.8")
    assert "AbuseIPDB" in result
    assert "VirusTotal" in result
    assert "Shodan" in result


def test_check_abuseipdb_with_configured_key_parses_response(monkeypatch):
    import config
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "fake-key")
    import tools.threat_feeds as feeds
    importlib.reload(feeds)

    class FakeResp:
        def json(self):
            return {
                "data": {
                    "abuseConfidenceScore": 92,
                    "totalReports": 47,
                    "isp": "Evil Corp",
                    "countryCode": "XX",
                }
            }

    monkeypatch.setattr(feeds.requests, "get", lambda *a, **k: FakeResp())

    result = feeds.check_abuseipdb("1.2.3.4")
    assert "92/100" in result
    assert "risco ALTO" in result
    assert "47 denúncia" in result
    importlib.reload(feeds)


def test_check_virustotal_ip_with_configured_key_parses_response(monkeypatch):
    import config
    monkeypatch.setattr(config, "VIRUSTOTAL_API_KEY", "fake-key")
    import tools.threat_feeds as feeds
    importlib.reload(feeds)

    class FakeResp:
        def json(self):
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 5, "suspicious": 2, "harmless": 70},
                        "as_owner": "Evil Corp",
                    }
                }
            }

    monkeypatch.setattr(feeds.requests, "get", lambda *a, **k: FakeResp())

    result = feeds.check_virustotal_ip("1.2.3.4")
    assert "5/77" in result
    importlib.reload(feeds)


def test_check_virustotal_hash_not_found(monkeypatch):
    import config
    monkeypatch.setattr(config, "VIRUSTOTAL_API_KEY", "fake-key")
    import tools.threat_feeds as feeds
    importlib.reload(feeds)

    class FakeResp:
        status_code = 404
        def json(self):
            return {}

    monkeypatch.setattr(feeds.requests, "get", lambda *a, **k: FakeResp())

    result = feeds.check_virustotal_hash("deadbeef")
    assert "não encontrado" in result
    importlib.reload(feeds)


def test_check_shodan_with_configured_key_parses_response(monkeypatch):
    import config
    monkeypatch.setattr(config, "SHODAN_API_KEY", "fake-key")
    import tools.threat_feeds as feeds
    importlib.reload(feeds)

    class FakeResp:
        status_code = 200
        def json(self):
            return {"ports": [22, 80, 443], "org": "Evil Corp", "hostnames": ["evil.example.com"], "vulns": []}

    monkeypatch.setattr(feeds.requests, "get", lambda *a, **k: FakeResp())

    result = feeds.check_shodan("1.2.3.4")
    assert "22" in result and "80" in result and "443" in result
    assert "evil.example.com" in result
    importlib.reload(feeds)


def test_network_failure_does_not_raise(monkeypatch):
    import config
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "fake-key")
    import tools.threat_feeds as feeds
    importlib.reload(feeds)

    import requests
    def raise_error(*a, **k):
        raise requests.RequestException("boom")

    monkeypatch.setattr(feeds.requests, "get", raise_error)

    result = feeds.check_abuseipdb("1.2.3.4")
    assert "Falha ao consultar" in result
    importlib.reload(feeds)
