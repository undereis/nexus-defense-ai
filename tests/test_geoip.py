import importlib

import pytest


@pytest.fixture
def geoip_module():
    import tools.geoip as geoip
    importlib.reload(geoip)
    yield geoip
    importlib.reload(geoip)


@pytest.mark.parametrize("ip", ["127.0.0.1", "192.168.1.1", "10.0.0.5", "::1", "169.254.1.1"])
def test_private_and_loopback_have_no_geolocation(geoip_module, ip):
    assert geoip_module.lookup(ip) is None


def test_invalid_ip_returns_none(geoip_module):
    assert geoip_module.lookup("not-an-ip") is None


def test_lookup_success_parses_fields(geoip_module, monkeypatch):
    class FakeResp:
        def json(self):
            return {
                "status": "success",
                "country": "United States",
                "regionName": "California",
                "city": "Mountain View",
                "isp": "Google LLC",
                "org": "Google",
                "as": "AS15169 Google LLC",
                "lat": 37.4,
                "lon": -122.1,
            }

    monkeypatch.setattr(geoip_module.requests, "get", lambda *a, **k: FakeResp())
    result = geoip_module.lookup("8.8.8.8")
    assert result["country"] == "United States"
    assert result["isp"] == "Google LLC"
    assert result["asn"] == "AS15169 Google LLC"


def test_lookup_caches_result(geoip_module, monkeypatch):
    calls = []

    class FakeResp:
        def json(self):
            calls.append(1)
            return {"status": "success", "country": "X", "regionName": "", "city": "", "isp": "Y", "as": "Z"}

    monkeypatch.setattr(geoip_module.requests, "get", lambda *a, **k: FakeResp())
    geoip_module.lookup("8.8.8.8")
    geoip_module.lookup("8.8.8.8")
    assert len(calls) == 1  # segunda chamada usa cache, não bate na API


def test_lookup_failure_returns_none(geoip_module, monkeypatch):
    class FakeResp:
        def json(self):
            return {"status": "fail", "message": "invalid query"}

    monkeypatch.setattr(geoip_module.requests, "get", lambda *a, **k: FakeResp())
    assert geoip_module.lookup("8.8.8.8") is None


def test_lookup_network_error_returns_none(geoip_module, monkeypatch):
    import requests

    def raise_error(*a, **k):
        raise requests.RequestException("boom")

    monkeypatch.setattr(geoip_module.requests, "get", raise_error)
    assert geoip_module.lookup("8.8.8.8") is None


def test_describe_location_for_private_ip(geoip_module):
    result = geoip_module.describe_location("192.168.1.1")
    assert "sem geolocalização" in result


def test_describe_location_for_public_ip(geoip_module, monkeypatch):
    class FakeResp:
        def json(self):
            return {
                "status": "success", "country": "Brazil", "regionName": "SP",
                "city": "Sao Paulo", "isp": "Provider X", "as": "AS123 Provider X",
            }

    monkeypatch.setattr(geoip_module.requests, "get", lambda *a, **k: FakeResp())
    result = geoip_module.describe_location("45.187.68.91")
    assert "Sao Paulo" in result
    assert "Provider X" in result
