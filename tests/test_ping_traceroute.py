"""Testes para ping_host/traceroute_host — diagnóstico real, não mock,
contra localhost (sempre disponível e sem depender de rede externa)."""

import re
import shutil

import pytest

from tools.access import ping_host, traceroute_host


def test_ping_host_against_localhost():
    result = ping_host("127.0.0.1", count=2)
    assert "2 packets transmitted" in result
    assert re.search(r"\b0(?:\.0)?% packet loss", result)


def test_ping_host_rejects_invalid_host():
    with pytest.raises(ValueError):
        ping_host("not a valid host")


def test_ping_host_clamps_count():
    result = ping_host("127.0.0.1", count=100)
    assert "10 packets transmitted" in result  # clamp em 10


def test_traceroute_host_against_localhost():
    if shutil.which("traceroute") is None:
        pytest.skip("traceroute não está instalado neste runner")
    result = traceroute_host("127.0.0.1", max_hops=5)
    assert "127.0.0.1" in result or "localhost" in result


def test_traceroute_host_rejects_invalid_host():
    with pytest.raises(ValueError):
        traceroute_host("not a valid host")
