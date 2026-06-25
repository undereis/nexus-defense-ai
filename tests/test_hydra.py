import importlib

import pytest


@pytest.fixture
def hydra_module(monkeypatch):
    import config
    monkeypatch.setattr(config, "ALLOW_ACTIVE_EXPLOITATION", True)
    import tools.hydra as hydra_mod
    importlib.reload(hydra_mod)
    monkeypatch.setattr(hydra_mod.shutil, "which", lambda name: "/usr/bin/hydra")
    yield hydra_mod
    importlib.reload(hydra_mod)


def test_disabled_by_default(monkeypatch):
    import config
    monkeypatch.setattr(config, "ALLOW_ACTIVE_EXPLOITATION", False)
    import importlib
    import tools.hydra as hydra_mod
    importlib.reload(hydra_mod)

    result = hydra_mod.brute_force_login("1.2.3.4", "ssh", username="root", password="x")
    assert "DESATIVADO" in result
    importlib.reload(hydra_mod)


def test_rejects_unsupported_service(hydra_module):
    result = hydra_module.brute_force_login("1.2.3.4", "telnet-fake", username="root", password="x")
    assert "não suportado" in result


def test_requires_username_or_userlist(hydra_module):
    result = hydra_module.brute_force_login("1.2.3.4", "ssh", password="x")
    assert "username ou userlist" in result


def test_requires_password_or_wordlist(hydra_module):
    result = hydra_module.brute_force_login("1.2.3.4", "ssh", username="root")
    assert "password ou wordlist" in result


def test_rejects_invalid_target(hydra_module):
    result = hydra_module.brute_force_login("1.2.3.4; rm -rf /", "ssh", username="root", password="x")
    assert "inválido" in result


def test_http_form_requires_path(hydra_module):
    result = hydra_module.brute_force_login(
        "1.2.3.4", "http-post-form", username="root", password="x"
    )
    assert "http_form_path" in result


def test_builds_correct_command_for_ssh(hydra_module, monkeypatch):
    captured = {}

    class FakeResult:
        stdout = "[2222][ssh] host: 1.2.3.4   login: root   password: senha123"
        stderr = ""

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return FakeResult()

    monkeypatch.setattr(hydra_module.subprocess, "run", fake_run)
    result = hydra_module.brute_force_login(
        "1.2.3.4", "ssh", username="root", password="senha123", port="2222"
    )
    assert "-l" in captured["cmd"] and "root" in captured["cmd"]
    assert "-p" in captured["cmd"] and "senha123" in captured["cmd"]
    assert "-s" in captured["cmd"] and "2222" in captured["cmd"]
    assert captured["cmd"][-2:] == ["1.2.3.4", "ssh"]
    assert "senha123" in result
