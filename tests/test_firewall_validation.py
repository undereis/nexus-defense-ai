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
    monkeypatch.setattr("tools.firewall.log_event", lambda *a, **k: None)

    from tools.firewall import block_ip

    result = block_ip("1.2.3.4", "teste")
    assert "1.2.3.4" in captured["cmd"]
    assert "isolado" in result.lower() or "bloqueado" in result.lower()


def test_block_ip_rejects_invalid_ip_before_running_pfctl(monkeypatch):
    called = {"n": 0}

    def fake_run(cmd):
        called["n"] += 1

    monkeypatch.setattr("tools.firewall._run", fake_run)
    monkeypatch.setattr("tools.firewall.log_event", lambda *a, **k: None)

    from tools.firewall import block_ip

    with pytest.raises(ValueError):
        block_ip("not-an-ip")
    assert called["n"] == 0


def test_block_ip_logs_attempt_and_confirmation(monkeypatch):
    logged = []

    def fake_run(cmd):
        class R:
            returncode = 0
            stderr = ""
        return R()

    monkeypatch.setattr("tools.firewall._run", fake_run)
    monkeypatch.setattr("tools.firewall.record_blocked_ip", lambda ip, reason: None)
    monkeypatch.setattr("tools.firewall.log_event", lambda *a, **k: logged.append(a))

    from tools.firewall import block_ip
    block_ip("1.2.3.4", "teste")

    event_types = [a[0] for a in logged]
    assert "firewall_block_attempt" in event_types
    assert "firewall_block_confirmed" in event_types


def test_unblock_ip_logs_attempt_and_confirmation(monkeypatch):
    logged = []

    def fake_run(cmd):
        class R:
            returncode = 0
            stderr = ""
        return R()

    monkeypatch.setattr("tools.firewall._run", fake_run)
    monkeypatch.setattr("tools.firewall.remove_blocked_ip", lambda ip: None)
    monkeypatch.setattr("tools.firewall.log_event", lambda *a, **k: logged.append(a))

    from tools.firewall import unblock_ip
    unblock_ip("1.2.3.4")

    event_types = [a[0] for a in logged]
    assert "firewall_unblock_attempt" in event_types
    assert "firewall_unblock_confirmed" in event_types


def test_block_ip_logs_failure_when_pfctl_fails(monkeypatch):
    logged = []

    def fake_run(cmd):
        class R:
            returncode = 1
            stderr = "erro de teste"
        return R()

    monkeypatch.setattr("tools.firewall._run", fake_run)
    monkeypatch.setattr("tools.firewall.log_event", lambda *a, **k: logged.append(a))

    from tools.firewall import block_ip
    result = block_ip("1.2.3.4", "teste")

    assert "Falha" in result
    event_types = [a[0] for a in logged]
    assert "firewall_block_failed" in event_types
