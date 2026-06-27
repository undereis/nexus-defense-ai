"""Testes para tools/bgp_flowspec.py.

A construção/validação da regra (RFC 5575) é testada de verdade, sem
mock. O envio para um BGP speaker real (ExaBGP) NUNCA foi validado
neste ambiente (não está instalado, sem sessão de trânsito) — ver
aviso no módulo. _send_to_exabgp sem EXABGP_API_PIPE configurado é
testado contra o comportamento real (retorna aviso, não finge sucesso).
"""

import importlib

import pytest

from tools import bgp_flowspec


@pytest.fixture
def flowspec_module(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_flowspec.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    monkeypatch.setattr(config, "EXABGP_API_PIPE", "")
    import tools.bgp_flowspec as fs
    importlib.reload(fs)
    yield fs, dbmod


def test_build_rule_with_minimal_fields(flowspec_module):
    fs, _ = flowspec_module
    rule = fs.build_rule("203.0.113.5/32")
    assert "destination 203.0.113.5/32;" in rule["rule_text"]
    assert "discard;" in rule["rule_text"]
    assert "destino=203.0.113.5/32" in rule["description"]


def test_build_rule_normalizes_single_ip_to_cidr(flowspec_module):
    fs, _ = flowspec_module
    rule = fs.build_rule("203.0.113.5")
    assert "203.0.113.5/32" in rule["rule_text"]


def test_build_rule_with_protocol_and_port(flowspec_module):
    fs, _ = flowspec_module
    rule = fs.build_rule("203.0.113.5/32", protocol="tcp", dest_port="80,443")
    assert "protocol tcp;" in rule["rule_text"]
    assert "destination-port 80,443;" in rule["rule_text"]


def test_build_rule_with_rate_limit(flowspec_module):
    fs, _ = flowspec_module
    rule = fs.build_rule("203.0.113.5/32", action="rate-limit", rate_limit_bps=1_000_000)
    assert "rate-limit 1000000;" in rule["rule_text"]


def test_build_rule_rejects_invalid_prefix(flowspec_module):
    fs, _ = flowspec_module
    with pytest.raises(ValueError, match="Prefixo IP inválido"):
        fs.build_rule("not-an-ip")


def test_build_rule_rejects_invalid_protocol(flowspec_module):
    fs, _ = flowspec_module
    with pytest.raises(ValueError, match="Protocolo inválido"):
        fs.build_rule("203.0.113.5/32", protocol="ftp")


def test_build_rule_rejects_invalid_action(flowspec_module):
    fs, _ = flowspec_module
    with pytest.raises(ValueError, match="Action inválida"):
        fs.build_rule("203.0.113.5/32", action="delete-everything")


def test_build_rule_rejects_rate_limit_without_bps(flowspec_module):
    fs, _ = flowspec_module
    with pytest.raises(ValueError, match="rate_limit_bps"):
        fs.build_rule("203.0.113.5/32", action="rate-limit")


def test_build_rule_rejects_invalid_port_syntax(flowspec_module):
    fs, _ = flowspec_module
    with pytest.raises(ValueError, match="Porta"):
        fs.build_rule("203.0.113.5/32", dest_port="80; rm -rf /")


def test_build_rule_rejects_command_injection_in_prefix(flowspec_module):
    fs, _ = flowspec_module
    with pytest.raises(ValueError):
        fs.build_rule("203.0.113.5/32; rm -rf /")


def test_announce_without_exabgp_configured_is_honest(flowspec_module):
    fs, _ = flowspec_module
    result = fs.announce_flowspec_rule("203.0.113.5/32", action="discard")
    assert "registrada" in result
    assert "NÃO foi enviada" in result
    assert "EXABGP_API_PIPE não configurado" in result


def test_announce_then_list_then_withdraw(flowspec_module):
    fs, _ = flowspec_module
    fs.announce_flowspec_rule("203.0.113.5/32", action="discard")

    listing = fs.list_active_rules()
    assert "203.0.113.5/32" in listing

    rule_id = 1
    withdraw_result = fs.withdraw_flowspec_rule(rule_id)
    assert "retirada" in withdraw_result

    listing_after = fs.list_active_rules()
    assert "Nenhuma regra FlowSpec ativa" in listing_after


def test_withdraw_unknown_rule(flowspec_module):
    fs, _ = flowspec_module
    result = fs.withdraw_flowspec_rule(999)
    assert "não encontrada" in result


def test_withdraw_already_withdrawn_rule(flowspec_module):
    fs, _ = flowspec_module
    fs.announce_flowspec_rule("203.0.113.5/32", action="discard")
    fs.withdraw_flowspec_rule(1)
    result = fs.withdraw_flowspec_rule(1)
    assert "já está com status" in result


def test_send_to_exabgp_writes_to_configured_pipe(flowspec_module, monkeypatch, tmp_path):
    fs, _ = flowspec_module
    fake_pipe = tmp_path / "exabgp_pipe"
    fake_pipe.write_text("")  # arquivo normal funciona igual a um named pipe pra teste de escrita
    monkeypatch.setattr(fs, "EXABGP_API_PIPE", str(fake_pipe))
    monkeypatch.setattr(fs.shutil, "which", lambda name: None)  # força o caminho de escrita direta no pipe

    result = fs._send_to_exabgp("announce flow route { ... }")
    assert "escrito no pipe" in result
    assert "announce flow route" in fake_pipe.read_text()
