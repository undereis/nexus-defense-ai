"""Testes para tools/dns_monitor.py — monitoramento dos DNS servers."""

import pytest

from tools import dns_monitor, infrastructure


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    import database.db as db_module
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    db_module.init_db()
    yield


def _dig_output(status: str = "NOERROR", latency: int = 12) -> str:
    return (
        ";; ->>HEADER<<- opcode: QUERY, status: " + status + ", id: 1\n"
        ";; flags: qr rd ra; QUERY: 1, ANSWER: 1\n"
        f";; Query time: {latency} msec\n"
    )


def _only_ports(*open_ports):
    """Fabrica um _check_port que considera abertas só as portas dadas."""
    allowed = set(open_ports)
    return lambda host, port, timeout=2.0: port in allowed


# ---------- cadastro ----------

def test_register_and_list_dns_server():
    result = dns_monitor.register_dns_server("192.168.0.90", "dns1", "Resolver primário")
    assert "192.168.0.90" in result
    listed = dns_monitor.list_dns_servers()
    assert "192.168.0.90" in listed
    assert "dns1" in listed


def test_register_invalid_ip_rejected():
    result = dns_monitor.register_dns_server("nao-eh-ip")
    assert "inválido" in result.lower()


def test_register_marks_ip_as_critical():
    assert not infrastructure.is_critical_ip("192.168.0.91")
    dns_monitor.register_dns_server("192.168.0.91", "dns2")
    assert infrastructure.is_critical_ip("192.168.0.91")


def test_unregister_dns_server():
    dns_monitor.register_dns_server("192.168.0.92")
    dns_monitor.unregister_dns_server("192.168.0.92")
    assert "192.168.0.92" not in dns_monitor.list_dns_servers()


def test_list_empty():
    assert "Nenhum DNS server" in dns_monitor.list_dns_servers()


# ---------- health check ----------

def test_healthy_resolver_reports_ok(monkeypatch):
    monkeypatch.setattr(dns_monitor, "_run_dig", lambda *a, **kw: _dig_output("NOERROR", 12))
    monkeypatch.setattr(dns_monitor, "_check_port", _only_ports(53))
    result = dns_monitor.check_dns_health("192.168.0.90")
    assert "[OK]" in result
    assert "⚠" not in result


def test_unreachable_resolver_flagged(monkeypatch):
    monkeypatch.setattr(dns_monitor, "_run_dig", lambda *a, **kw: "")
    monkeypatch.setattr(dns_monitor, "_check_port", _only_ports())
    result = dns_monitor.check_dns_health("192.168.0.90")
    assert "[PROBLEMA]" in result
    assert "não respondeu" in result


def test_servfail_flagged(monkeypatch):
    monkeypatch.setattr(dns_monitor, "_run_dig", lambda *a, **kw: _dig_output("SERVFAIL", 5))
    monkeypatch.setattr(dns_monitor, "_check_port", _only_ports(53))
    result = dns_monitor.check_dns_health("192.168.0.90")
    assert "[PROBLEMA]" in result
    assert "SERVFAIL" in result


def test_high_latency_flagged(monkeypatch):
    monkeypatch.setattr(dns_monitor, "_run_dig", lambda *a, **kw: _dig_output("NOERROR", 900))
    monkeypatch.setattr(dns_monitor, "_check_port", _only_ports(53))
    result = dns_monitor.check_dns_health("192.168.0.90")
    assert "[PROBLEMA]" in result
    assert "latência alta" in result


def test_risky_port_open_flagged(monkeypatch):
    monkeypatch.setattr(dns_monitor, "_run_dig", lambda *a, **kw: _dig_output("NOERROR", 10))
    # 53 (ok) + 23 telnet (red flag) abertos.
    monkeypatch.setattr(dns_monitor, "_check_port", _only_ports(53, 23))
    result = dns_monitor.check_dns_health("192.168.0.90")
    assert "[PROBLEMA]" in result
    assert "risco" in result and "23" in result


def test_cert_expiring_soon_flagged(monkeypatch):
    monkeypatch.setattr(dns_monitor, "_run_dig", lambda *a, **kw: _dig_output("NOERROR", 10))
    monkeypatch.setattr(dns_monitor, "_check_port", _only_ports(53, 853))
    monkeypatch.setattr(
        dns_monitor, "_check_cert",
        lambda host, port=853, timeout=3.0: {"ok": True, "days_left": 7},
    )
    result = dns_monitor.check_dns_health("192.168.0.90")
    assert "[PROBLEMA]" in result
    assert "expira em 7" in result


def test_cert_expired_flagged(monkeypatch):
    monkeypatch.setattr(dns_monitor, "_run_dig", lambda *a, **kw: _dig_output("NOERROR", 10))
    monkeypatch.setattr(dns_monitor, "_check_port", _only_ports(53, 443))
    monkeypatch.setattr(
        dns_monitor, "_check_cert",
        lambda host, port=853, timeout=3.0: {"ok": True, "days_left": -3},
    )
    result = dns_monitor.check_dns_health("192.168.0.90")
    assert "[PROBLEMA]" in result
    assert "EXPIRADO" in result


def test_cert_valid_no_problem(monkeypatch):
    monkeypatch.setattr(dns_monitor, "_run_dig", lambda *a, **kw: _dig_output("NOERROR", 10))
    monkeypatch.setattr(dns_monitor, "_check_port", _only_ports(53, 853))
    monkeypatch.setattr(
        dns_monitor, "_check_cert",
        lambda host, port=853, timeout=3.0: {"ok": True, "days_left": 200},
    )
    result = dns_monitor.check_dns_health("192.168.0.90")
    assert "[OK]" in result


# ---------- agregado + histórico ----------

def test_check_all_no_servers():
    assert "Nenhum DNS server" in dns_monitor.check_all_dns_health()


def test_check_all_aggregates(monkeypatch):
    dns_monitor.register_dns_server("192.168.0.90", "dns1")
    dns_monitor.register_dns_server("192.168.0.91", "dns2")
    monkeypatch.setattr(dns_monitor, "_run_dig", lambda *a, **kw: _dig_output("NOERROR", 10))
    monkeypatch.setattr(dns_monitor, "_check_port", _only_ports(53))
    result = dns_monitor.check_all_dns_health()
    assert "192.168.0.90" in result
    assert "192.168.0.91" in result


def test_health_check_recorded_in_history(monkeypatch):
    dns_monitor.register_dns_server("192.168.0.90", "dns1")
    monkeypatch.setattr(dns_monitor, "_run_dig", lambda *a, **kw: _dig_output("NOERROR", 10))
    monkeypatch.setattr(dns_monitor, "_check_port", _only_ports(53))
    dns_monitor.check_dns_health("192.168.0.90")
    history = dns_monitor.describe_dns_health_history("192.168.0.90")
    assert "192.168.0.90" in history
    assert "NOERROR" in history


def test_history_empty():
    assert "Nenhuma verificação" in dns_monitor.describe_dns_health_history()


# ---------- parsers / helpers ----------

def test_parse_dig_extracts_status_and_latency():
    parsed = dns_monitor._parse_dig(_dig_output("NOERROR", 42))
    assert parsed["reachable"] is True
    assert parsed["status"] == "NOERROR"
    assert parsed["latency_ms"] == 42


def test_parse_dig_empty_is_unreachable():
    parsed = dns_monitor._parse_dig("")
    assert parsed["reachable"] is False
    assert parsed["latency_ms"] == -1


def test_has_problems_helper():
    assert dns_monitor.has_problems("DNS 1.2.3.4 [PROBLEMA] — ...")
    assert not dns_monitor.has_problems("DNS 1.2.3.4 [OK] — ...")
