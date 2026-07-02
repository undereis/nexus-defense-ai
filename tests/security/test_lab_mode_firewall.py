"""Risco crítico #1 — lab/replay NÃO executam ação real por caminho direto.

CINTO DE MODO (Fase 1B) aplicado: `tools/firewall.*` consulta o modo operacional e
vira no-op em lab/replay (ou modo indeterminado). Estes testes, que na Fase 1A eram
xfail (o bypass existia), agora são NORMAIS e passam.

Nenhum pfctl real é executado: o backend é substituído por um FAKE que só registra a
chamada.
"""

import pytest

import tools.firewall as firewall
from core import operating_mode


class _Result:
    """Imita o CompletedProcess que o backend real devolve."""

    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _FakeBackend:
    """Backend de firewall falso — registra chamadas, NUNCA toca o SO."""

    def __init__(self):
        self.block_calls: list[str] = []
        self.unblock_calls: list[str] = []
        self.rate_calls: list[str] = []

    def block(self, ip):
        self.block_calls.append(ip)
        return _Result(returncode=0)

    def unblock(self, ip):
        self.unblock_calls.append(ip)
        return _Result(returncode=0)

    def rate_limit(self, ip):
        self.rate_calls.append(ip)
        return _Result(returncode=0)

    def list_raw(self):
        return _Result(returncode=0, stdout="")

    def parse_ips(self, _out):
        return []


@pytest.fixture
def fake_backend(monkeypatch):
    fake = _FakeBackend()
    monkeypatch.setattr(firewall, "_backend", fake)
    return fake


# ------------------------- lab / replay: no-op -------------------------

def test_lab_mode_block_ip_must_not_touch_backend(fake_backend):
    operating_mode.set_operating_mode("lab")
    result = firewall.block_ip("203.0.113.5", "teste lab")
    assert fake_backend.block_calls == []               # backend real NÃO chamado
    assert "lab" in result.lower() and "dry" in result.lower()


def test_replay_mode_block_ip_must_not_touch_backend(fake_backend):
    operating_mode.set_operating_mode("replay")
    result = firewall.block_ip("203.0.113.6", "teste replay")
    assert fake_backend.block_calls == []
    assert "replay" in result.lower() and "dry" in result.lower()


def test_lab_mode_unblock_ip_is_noop(fake_backend):
    operating_mode.set_operating_mode("lab")
    result = firewall.unblock_ip("203.0.113.5")
    assert fake_backend.unblock_calls == []
    assert "dry" in result.lower()


def test_lab_mode_rate_limit_is_noop(fake_backend):
    operating_mode.set_operating_mode("lab")
    result = firewall.rate_limit_ip("203.0.113.5", "teste")
    assert fake_backend.rate_calls == []
    assert "dry" in result.lower()


# ------------------------- modo indeterminado (conservador) -------------------------

def test_mode_unavailable_is_conservative_noop(fake_backend, monkeypatch):
    """Se o modo não puder ser determinado (ex.: DB indisponível), a primitiva NÃO
    executa ação real (conservador — regra 6 da Fase 1B)."""
    def _raise():
        raise RuntimeError("system_state indisponível")

    monkeypatch.setattr(operating_mode, "get_operating_mode", _raise)
    result = firewall.block_ip("203.0.113.8", "modo indeterminado")
    assert fake_backend.block_calls == []
    assert "dry" in result.lower()


# ------------------------- real: comportamento preservado -------------------------

def test_real_mode_block_ip_reaches_backend(fake_backend):
    """Safety net: em modo REAL o backend É chamado — o cinto não pode transformar
    o modo real em no-op."""
    operating_mode.set_operating_mode("real")
    firewall.block_ip("203.0.113.7", "teste real")
    assert fake_backend.block_calls == ["203.0.113.7"]
