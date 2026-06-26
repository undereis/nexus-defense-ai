"""Testes do backend Linux (iptables/ipset) — só cobertura via mock de
subprocess, porque o ambiente de desenvolvimento é macOS. NUNCA validado
contra um Linux real; ver aviso em tools/firewall_backends/iptables.py."""

from tools.firewall_backends import iptables


class _FakeResult:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_setup_creates_ipset_and_inserts_rule_when_missing(monkeypatch):
    calls = []

    def fake_run(cmd):
        calls.append(cmd)
        if cmd[:3] == ["sudo", "iptables", "-C"]:
            return _FakeResult(returncode=1)  # regra ainda não existe
        return _FakeResult(returncode=0)

    monkeypatch.setattr(iptables, "_run", fake_run)
    result = iptables.setup()

    assert "configurado e ativo" in result
    assert any(c[:3] == ["sudo", "ipset", "create"] for c in calls)
    assert any(c[:3] == ["sudo", "iptables", "-I"] for c in calls)


def test_setup_skips_insert_when_rule_already_exists(monkeypatch):
    calls = []

    def fake_run(cmd):
        calls.append(cmd)
        return _FakeResult(returncode=0)  # -C já retorna sucesso: regra existe

    monkeypatch.setattr(iptables, "_run", fake_run)
    iptables.setup()

    assert not any(c[:3] == ["sudo", "iptables", "-I"] for c in calls)


def test_block_calls_ipset_add():
    import tools.firewall_backends.iptables as mod
    captured = {}

    def fake_run(cmd):
        captured["cmd"] = cmd
        return _FakeResult(returncode=0)

    mod._run = fake_run
    result = mod.block("198.51.100.7")
    assert captured["cmd"] == ["sudo", "ipset", "add", "nexus_blocklist", "198.51.100.7", "-exist"]
    assert result.returncode == 0


def test_unblock_calls_ipset_del():
    import tools.firewall_backends.iptables as mod
    captured = {}

    def fake_run(cmd):
        captured["cmd"] = cmd
        return _FakeResult(returncode=0)

    mod._run = fake_run
    mod.unblock("198.51.100.7")
    assert captured["cmd"] == ["sudo", "ipset", "del", "nexus_blocklist", "198.51.100.7"]


def test_parse_ips_extracts_members_from_save_output():
    stdout = (
        "create nexus_blocklist hash:ip family inet hashsize 1024 maxelem 65536\n"
        "add nexus_blocklist 198.51.100.7\n"
        "add nexus_blocklist 203.0.113.9\n"
    )
    assert iptables.parse_ips(stdout) == ["198.51.100.7", "203.0.113.9"]


def test_parse_ips_empty_set():
    stdout = "create nexus_blocklist hash:ip family inet hashsize 1024 maxelem 65536\n"
    assert iptables.parse_ips(stdout) == []
