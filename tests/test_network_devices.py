"""Testes do executor multi-vendor (Linux/Cisco/Huawei/Ubiquiti) via SSH.

NUNCA VALIDADO CONTRA HARDWARE REAL — só cobertura via mock de
subprocess, igual ao backend iptables (ver aviso no módulo)."""

import pytest

from tools import network_devices


@pytest.mark.parametrize(
    "vendor,command,expected",
    [
        ("linux", "uptime", True),
        ("linux", "rm -rf /", False),
        ("linux", "useradd attacker", False),
        ("cisco_ios", "show version", True),
        ("cisco_ios", "show running-config", True),
        ("cisco_ios", "configure terminal", False),
        ("cisco_ios", "no shutdown", False),
        ("huawei_vrp", "display version", True),
        ("huawei_vrp", "display current-configuration", True),
        ("huawei_vrp", "system-view", False),
        ("ubiquiti_edgeos", "show interfaces", True),
        ("ubiquiti_edgeos", "set interfaces ethernet eth0 disable", False),
    ],
)
def test_is_safe_read_classification(vendor, command, expected):
    assert network_devices.is_safe_read(vendor, command) is expected


def test_run_read_command_rejects_unknown_vendor():
    result = network_devices.run_read_command("juniper_junos", "10.0.0.1", "show version")
    assert "Vendor desconhecido" in result


def test_run_read_command_rejects_unsafe_command():
    result = network_devices.run_read_command("cisco_ios", "10.0.0.1", "no shutdown")
    assert "não está na lista de comandos de leitura seguros" in result


class _FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_run_read_command_executes_safe_command(monkeypatch):
    captured = {}

    def fake_subprocess_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _FakeCompleted(returncode=0, stdout="Cisco IOS Software, Version 15.2\n")

    monkeypatch.setattr(network_devices.subprocess, "run", fake_subprocess_run)
    monkeypatch.setattr(network_devices, "SSH_USER", "admin")
    monkeypatch.setattr(network_devices, "SSH_KEY_PATH", "/fake/key")

    result = network_devices.run_read_command("cisco_ios", "10.0.0.1", "show version")

    assert "Cisco IOS Software" in result
    assert captured["cmd"][-1] == "show version"


def test_raw_ssh_requires_ssh_user(monkeypatch):
    monkeypatch.setattr(network_devices, "SSH_USER", "")
    result = network_devices._raw_ssh("10.0.0.1", "show version")
    assert "Nenhum usuário SSH configurado" in result
