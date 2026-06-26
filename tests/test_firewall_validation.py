import pytest

from tools.firewall import _validate_ip


@pytest.mark.parametrize("ip", ["1.2.3.4", "192.168.0.1", "::1", "2001:db8::1"])
def test_valid_ips_pass(ip):
    assert _validate_ip(ip) == ip


@pytest.mark.parametrize("ip", ["not-an-ip", "1.2.3.4; rm -rf /", "", "999.999.999.999"])
def test_invalid_ips_rejected(ip):
    with pytest.raises(ValueError):
        _validate_ip(ip)


class _FakeResult:
    def __init__(self, returncode=0, stderr=""):
        self.returncode = returncode
        self.stderr = stderr


def test_block_ip_calls_backend_with_validated_ip(monkeypatch):
    captured = {}

    def fake_block(ip):
        captured["ip"] = ip
        return _FakeResult()

    monkeypatch.setattr("tools.firewall._backend.block", fake_block)
    monkeypatch.setattr("tools.firewall.record_blocked_ip", lambda ip, reason: None)
    monkeypatch.setattr("tools.firewall.log_event", lambda *a, **k: None)

    from tools.firewall import block_ip

    result = block_ip("1.2.3.4", "teste")
    assert captured["ip"] == "1.2.3.4"
    assert "isolado" in result.lower() or "bloqueado" in result.lower()


def test_block_ip_rejects_invalid_ip_before_calling_backend(monkeypatch):
    called = {"n": 0}

    def fake_block(ip):
        called["n"] += 1
        return _FakeResult()

    monkeypatch.setattr("tools.firewall._backend.block", fake_block)
    monkeypatch.setattr("tools.firewall.log_event", lambda *a, **k: None)

    from tools.firewall import block_ip

    with pytest.raises(ValueError):
        block_ip("not-an-ip")
    assert called["n"] == 0


def test_block_ip_logs_attempt_and_confirmation(monkeypatch):
    logged = []

    monkeypatch.setattr("tools.firewall._backend.block", lambda ip: _FakeResult())
    monkeypatch.setattr("tools.firewall.record_blocked_ip", lambda ip, reason: None)
    monkeypatch.setattr("tools.firewall.log_event", lambda *a, **k: logged.append(a))

    from tools.firewall import block_ip
    block_ip("1.2.3.4", "teste")

    event_types = [a[0] for a in logged]
    assert "firewall_block_attempt" in event_types
    assert "firewall_block_confirmed" in event_types


def test_unblock_ip_logs_attempt_and_confirmation(monkeypatch):
    logged = []

    monkeypatch.setattr("tools.firewall._backend.unblock", lambda ip: _FakeResult())
    monkeypatch.setattr("tools.firewall.remove_blocked_ip", lambda ip: None)
    monkeypatch.setattr("tools.firewall.log_event", lambda *a, **k: logged.append(a))

    from tools.firewall import unblock_ip
    unblock_ip("1.2.3.4")

    event_types = [a[0] for a in logged]
    assert "firewall_unblock_attempt" in event_types
    assert "firewall_unblock_confirmed" in event_types


def test_block_ip_logs_failure_when_backend_fails(monkeypatch):
    logged = []

    monkeypatch.setattr(
        "tools.firewall._backend.block", lambda ip: _FakeResult(returncode=1, stderr="erro de teste")
    )
    monkeypatch.setattr("tools.firewall.log_event", lambda *a, **k: logged.append(a))

    from tools.firewall import block_ip
    result = block_ip("1.2.3.4", "teste")

    assert "Falha" in result
    event_types = [a[0] for a in logged]
    assert "firewall_block_failed" in event_types
