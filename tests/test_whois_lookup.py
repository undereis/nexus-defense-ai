"""Testes para tools/whois_lookup.py — whois e consulta de ASN reais,
contra serviços públicos de verdade (sem mock de rede), seguindo o
mesmo padrão de validação de tools/recon.py e tools/access.py."""

import pytest

from tools.whois_lookup import _validate_asn, _validate_target, asn_lookup, whois_query


@pytest.mark.parametrize("target", ["8.8.8.8", "google.com", "2001:4860:4860::8888"])
def test_validate_target_accepts_valid_inputs(target):
    assert _validate_target(target)


@pytest.mark.parametrize("target", ["rm -rf /; echo pwned", "", "not a target!!", "a" * 300])
def test_validate_target_rejects_invalid_inputs(target):
    with pytest.raises(ValueError):
        _validate_target(target)


@pytest.mark.parametrize("asn,expected", [("15169", "15169"), ("AS15169", "15169"), ("as15169", "15169")])
def test_validate_asn_accepts_with_or_without_prefix(asn, expected):
    assert _validate_asn(asn) == expected


@pytest.mark.parametrize("asn", ["not-an-asn", "AS", "15169; rm -rf /", ""])
def test_validate_asn_rejects_invalid_inputs(asn):
    with pytest.raises(ValueError):
        _validate_asn(asn)


@pytest.mark.integration
def test_whois_query_real_ip_returns_registry_data():
    result = whois_query("8.8.8.8")
    assert "GOGL" in result or "Google" in result or "ARIN" in result


@pytest.mark.integration
def test_whois_query_real_domain_returns_registry_data():
    result = whois_query("google.com")
    assert "VERISIGN" in result.upper() or "GOOGLE" in result.upper()


def test_whois_query_rejects_command_injection_attempt():
    with pytest.raises(ValueError):
        whois_query("$(rm -rf /)")


@pytest.mark.integration
def test_asn_lookup_real_known_asn_returns_holder_and_prefixes():
    result = asn_lookup("15169")
    assert "AS15169" in result
    assert "GOOGLE" in result.upper()
    assert "Prefixos anunciados" in result


@pytest.mark.integration
def test_asn_lookup_accepts_as_prefix():
    result = asn_lookup("AS15169")
    assert "AS15169" in result
