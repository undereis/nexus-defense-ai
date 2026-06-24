import pytest

from tools.firewall import _validate_ip


@pytest.mark.parametrize("ip", ["1.2.3.4", "192.168.0.1", "::1", "2001:db8::1"])
def test_valid_ips_pass(ip):
    assert _validate_ip(ip) == ip


@pytest.mark.parametrize("ip", ["not-an-ip", "1.2.3.4; rm -rf /", "", "999.999.999.999"])
def test_invalid_ips_rejected(ip):
    with pytest.raises(ValueError):
        _validate_ip(ip)


def test_block_ip_calls_pfctl_with_validated_ip(monkeypatch):
    captured = {}

    def fake_run(cmd):
        captured["cmd"] = cmd
        class R:
            returncode = 0
            stderr = ""
        return R()

    monkeypatch.setattr("tools.firewall._run", fake_run)
    monkeypatch.setattr("tools.firewall.record_blocked_ip", lambda ip, reason: None)

    from tools.firewall import block_ip

    result = block_ip("1.2.3.4", "teste")
    assert "1.2.3.4" in captured["cmd"]
    assert "isolado" in result.lower() or "bloqueado" in result.lower()


def test_block_ip_rejects_invalid_ip_before_running_pfctl(monkeypatch):
    called = {"n": 0}

    def fake_run(cmd):
        called["n"] += 1

    monkeypatch.setattr("tools.firewall._run", fake_run)

    from tools.firewall import block_ip

    with pytest.raises(ValueError):
        block_ip("not-an-ip")
    assert called["n"] == 0
