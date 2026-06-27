"""Testes para tools/dpi.py — wrapper de Suricata.

NUNCA VALIDADO CONTRA TRÁFEGO REAL (ver aviso no módulo). start/stop são
testados via mock de subprocess.Popen (Suricata não está instalado
aqui); o parser de eve.json é testado de verdade, sem mock, contra um
arquivo eve.json real de exemplo — essa parte não depende do binário."""

import json

import pytest

from tools import dpi


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch):
    monkeypatch.setattr(dpi, "_process", None)
    yield
    monkeypatch.setattr(dpi, "_process", None)


@pytest.fixture
def eve_json_file(tmp_path, monkeypatch):
    monkeypatch.setattr(dpi, "DPI_LOG_DIR", tmp_path)
    eve_path = tmp_path / "eve.json"
    lines = [
        {
            "timestamp": "2026-06-26T10:00:00.000000-0300",
            "event_type": "alert",
            "src_ip": "203.0.113.55", "src_port": 443, "dest_ip": "10.0.0.5", "dest_port": 51234,
            "alert": {"signature": "ET MALWARE Suspicious User-Agent", "category": "Malware", "severity": 1},
        },
        {
            "timestamp": "2026-06-26T10:01:00.000000-0300",
            "event_type": "flow",  # não é alerta, deve ser ignorado
            "src_ip": "10.0.0.5", "dest_ip": "8.8.8.8",
        },
        {
            "timestamp": "2026-06-26T10:02:00.000000-0300",
            "event_type": "alert",
            "src_ip": "198.51.100.9", "src_port": 22, "dest_ip": "10.0.0.5", "dest_port": 22,
            "alert": {"signature": "ET SCAN SSH BruteForce", "category": "Attempted Login", "severity": 2},
        },
        {
            "timestamp": "2026-06-26T10:03:00.000000-0300",
            "event_type": "alert",
            "src_ip": "203.0.113.55", "src_port": 443, "dest_ip": "10.0.0.5", "dest_port": 51235,
            "alert": {"signature": "ET MALWARE Suspicious User-Agent", "category": "Malware", "severity": 1},
        },
    ]
    with eve_path.open("w") as f:
        for entry in lines:
            f.write(json.dumps(entry) + "\n")
    # Linha corrompida de propósito, deve ser ignorada sem quebrar o parser.
    with eve_path.open("a") as f:
        f.write("isso não é json válido\n")
    yield eve_path


def test_is_running_false_when_no_process():
    assert dpi.is_running() is False


def test_start_requires_interface(monkeypatch):
    monkeypatch.setattr("config.DPI_INTERFACE", "")
    result = dpi.start("")
    assert "Nenhuma interface informada" in result


def test_start_reports_not_installed(monkeypatch):
    monkeypatch.setattr(dpi.shutil, "which", lambda name: None)
    result = dpi.start("eth0")
    assert "não está instalado" in result


def test_start_launches_subprocess_when_installed(monkeypatch, tmp_path):
    monkeypatch.setattr(dpi, "DPI_LOG_DIR", tmp_path)
    monkeypatch.setattr(dpi.shutil, "which", lambda name: "/usr/local/bin/suricata")

    captured = {}

    class FakePopen:
        def __init__(self, cmd, **kwargs):
            captured["cmd"] = cmd
            self.pid = 12345
        def poll(self):
            return None

    monkeypatch.setattr(dpi.subprocess, "Popen", FakePopen)

    result = dpi.start("eth0")
    assert "iniciado na interface eth0" in result
    assert captured["cmd"] == ["suricata", "-i", "eth0", "-l", str(tmp_path)]


def test_stop_when_not_running():
    assert dpi.stop() == "Suricata não está rodando."


def test_stop_terminates_running_process(monkeypatch):
    class FakeProcess:
        pid = 999
        def poll(self):
            return None
        def terminate(self):
            self.terminated = True
        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(dpi, "_process", FakeProcess())
    result = dpi.stop()
    assert "999" in result and "parado" in result
    assert dpi.is_running() is False


def test_list_alerts_with_no_log_file(tmp_path, monkeypatch):
    monkeypatch.setattr(dpi, "DPI_LOG_DIR", tmp_path)
    result = dpi.list_alerts()
    assert "Nenhum alerta" in result


def test_list_alerts_parses_real_eve_json_and_ignores_non_alerts(eve_json_file):
    result = dpi.list_alerts()
    assert "ET MALWARE Suspicious User-Agent" in result
    assert "ET SCAN SSH BruteForce" in result
    assert "203.0.113.55" in result
    assert "198.51.100.9" in result
    # Linhas event_type=flow não são alertas e não devem aparecer.
    assert result.count("[20") == 3  # 3 alertas, não 4 linhas totais


def test_list_alerts_respects_limit(eve_json_file):
    result = dpi.list_alerts(limit=1)
    assert result.count("ET ") == 1


def test_describe_alert_summary_aggregates_by_signature(eve_json_file):
    result = dpi.describe_alert_summary()
    assert "ET MALWARE Suspicious User-Agent: 2" in result
    assert "ET SCAN SSH BruteForce: 1" in result


def test_malformed_json_line_does_not_break_parser(eve_json_file):
    # Já incluída no fixture (linha "isso não é json válido") — se chegou
    # até aqui sem exception, o parser ignorou corretamente.
    result = dpi.describe_alert_summary()
    assert "ET" in result
