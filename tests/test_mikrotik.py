import importlib

import pytest


class FakeApi:
    def __init__(self, responses):
        self._responses = responses
        self.calls = []
        self.closed = False

    def __call__(self, cmd, **params):
        self.calls.append((cmd, params))
        return iter(self._responses.get(cmd, []))

    def close(self):
        self.closed = True


@pytest.fixture
def mikrotik_module(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_mikrotik.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    monkeypatch.setattr(config, "MIKROTIK_HOST", "192.168.88.1")
    monkeypatch.setattr(config, "MIKROTIK_USER", "admin")
    monkeypatch.setattr(config, "MIKROTIK_PASSWORD", "secretpass")

    import tools.mikrotik as mikrotik
    importlib.reload(mikrotik)
    yield mikrotik, dbmod


def _patch_connect(monkeypatch, mikrotik_mod, responses):
    fake = FakeApi(responses)
    monkeypatch.setattr(mikrotik_mod, "_connect", lambda: fake)
    return fake


def test_not_configured_blocks_test_connection(monkeypatch):
    import config
    monkeypatch.setattr(config, "MIKROTIK_HOST", "")
    import importlib
    import tools.mikrotik as mikrotik
    importlib.reload(mikrotik)

    result = mikrotik.test_connection()
    assert "não configurado" in result
    importlib.reload(mikrotik)


def test_connection_success(mikrotik_module, monkeypatch):
    mikrotik, _ = mikrotik_module
    _patch_connect(monkeypatch, mikrotik, {"/system/identity/print": [{"name": "RB750-Ramon"}]})

    result = mikrotik.test_connection()
    assert "Conexão OK" in result
    assert "RB750-Ramon" in result


def test_connection_failure_reports_error(mikrotik_module, monkeypatch):
    mikrotik, _ = mikrotik_module

    def raise_error():
        raise ConnectionError("timeout")

    monkeypatch.setattr(mikrotik, "_connect", raise_error)
    result = mikrotik.test_connection()
    assert "Falha ao conectar" in result


def test_get_system_resources(mikrotik_module, monkeypatch):
    mikrotik, _ = mikrotik_module
    _patch_connect(monkeypatch, mikrotik, {
        "/system/resource/print": [{
            "cpu-load": "5", "free-memory": "100000", "total-memory": "256000",
            "uptime": "3d5h", "version": "6.49.10", "board-name": "RB750Gr3",
        }]
    })
    result = mikrotik.get_system_resources()
    assert "CPU: 5%" in result
    assert "RB750Gr3" in result


def test_list_interfaces(mikrotik_module, monkeypatch):
    mikrotik, _ = mikrotik_module
    _patch_connect(monkeypatch, mikrotik, {
        "/interface/print": [
            {"name": "ether1", "type": "ether", "running": True},
            {"name": "ether2", "type": "ether", "running": False},
        ]
    })
    result = mikrotik.list_interfaces()
    assert "ether1: ether — rodando" in result
    assert "ether2: ether — parada" in result


def test_add_firewall_rule_rejects_invalid_chain(mikrotik_module):
    mikrotik, _ = mikrotik_module
    result = mikrotik.add_firewall_rule("invalida", "drop")
    assert "chain inválida" in result


def test_add_firewall_rule_rejects_invalid_action(mikrotik_module):
    mikrotik, _ = mikrotik_module
    result = mikrotik.add_firewall_rule("input", "invalida")
    assert "action inválida" in result


def test_add_firewall_rule_success_and_audited(mikrotik_module, monkeypatch):
    mikrotik, dbmod = mikrotik_module
    fake = _patch_connect(monkeypatch, mikrotik, {"/ip/firewall/filter/add": []})

    result = mikrotik.add_firewall_rule("input", "drop", src_address="45.187.68.91", comment="teste")
    assert "Regra adicionada" in result
    assert fake.calls[0][0] == "/ip/firewall/filter/add"
    assert fake.calls[0][1]["src-address"] == "45.187.68.91"
    assert fake.closed is True

    events = dbmod.get_all_events()
    types = [e[2] for e in events]
    assert "mikrotik_firewall_add" in types
    assert "mikrotik_firewall_add_confirmed" in types


def test_list_firewall_rules_filters_by_chain(mikrotik_module, monkeypatch):
    mikrotik, _ = mikrotik_module
    _patch_connect(monkeypatch, mikrotik, {
        "/ip/firewall/filter/print": [
            {".id": "*1", "chain": "input", "action": "drop"},
            {".id": "*2", "chain": "forward", "action": "accept"},
        ]
    })
    result = mikrotik.list_firewall_rules(chain="input")
    assert "*1" in result
    assert "*2" not in result


def test_create_pppoe_user_audited_without_leaking_password(mikrotik_module, monkeypatch):
    mikrotik, dbmod = mikrotik_module
    _patch_connect(monkeypatch, mikrotik, {"/ppp/secret/add": []})

    result = mikrotik.create_pppoe_user("cliente1", "minhasenha123", "default")
    assert "cliente1" in result

    events = dbmod.get_all_events()
    detail_blob = " ".join(e[4] for e in events)
    assert "minhasenha123" not in detail_blob


def test_remove_pppoe_user_not_found(mikrotik_module, monkeypatch):
    mikrotik, _ = mikrotik_module
    _patch_connect(monkeypatch, mikrotik, {"/ppp/secret/print": []})
    result = mikrotik.remove_pppoe_user("inexistente")
    assert "não encontrado" in result


def test_remove_pppoe_user_success(mikrotik_module, monkeypatch):
    mikrotik, dbmod = mikrotik_module
    _patch_connect(monkeypatch, mikrotik, {
        "/ppp/secret/print": [{".id": "*5", "name": "cliente1"}],
        "/ppp/secret/remove": [],
    })
    result = mikrotik.remove_pppoe_user("cliente1")
    assert "removido" in result


def test_run_generic_command_is_audited(mikrotik_module, monkeypatch):
    mikrotik, dbmod = mikrotik_module
    _patch_connect(monkeypatch, mikrotik, {"/ip/address/print": [{"address": "10.0.0.1/24"}]})

    result = mikrotik.run_generic_command("/ip/address/print")
    assert "10.0.0.1/24" in result

    events = dbmod.get_all_events()
    types = [e[2] for e in events]
    assert "mikrotik_generic_command" in types
    assert "mikrotik_generic_command_confirmed" in types
