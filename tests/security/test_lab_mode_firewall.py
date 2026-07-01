"""Risco crítico #1 — lab/replay NÃO podem executar ação real por caminho direto.

Caracteriza a primitiva `tools/firewall.block_ip`: em modo lab/replay ela deveria
virar no-op (não tocar o backend real). HOJE ela ignora o modo operacional e chama
o backend — por isso os testes de lab/replay são xfail(strict=True): quando a Fase A
os corrigir, eles passam e o strict avisa "remova o xfail".

Nenhum pfctl real é executado: o backend é substituído por um FAKE que só registra
a chamada.
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

    def block(self, ip):
        self.block_calls.append(ip)
        return _Result(returncode=0)

    def unblock(self, ip):
        self.unblock_calls.append(ip)
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


@pytest.mark.xfail(strict=True, reason=(
    "BYPASS Fase 0: firewall.block_ip não consulta operating_mode; em LAB ele chama "
    "o backend real. A Fase A deve fazer a primitiva virar no-op em lab/replay."))
def test_lab_mode_block_ip_must_not_touch_backend(fake_backend):
    operating_mode.set_operating_mode("lab")
    result = firewall.block_ip("203.0.113.5", "teste lab")
    # Comportamento FUTURO esperado (hoje falha -> xfail):
    assert fake_backend.block_calls == []               # backend real NÃO chamado
    assert "lab" in result.lower() or "dry" in result.lower()


@pytest.mark.xfail(strict=True, reason=(
    "BYPASS Fase 0: firewall.block_ip não consulta operating_mode; em REPLAY ele chama "
    "o backend real. A Fase A deve fazer a primitiva virar no-op em lab/replay."))
def test_replay_mode_block_ip_must_not_touch_backend(fake_backend):
    operating_mode.set_operating_mode("replay")
    result = firewall.block_ip("203.0.113.6", "teste replay")
    assert fake_backend.block_calls == []
    assert "replay" in result.lower() or "dry" in result.lower()


def test_real_mode_block_ip_reaches_backend(fake_backend):
    """Safety net (passa HOJE): em modo REAL o backend É chamado. Protege o caminho
    legítimo — a Fase A não pode transformar o modo real em no-op por engano."""
    operating_mode.set_operating_mode("real")
    firewall.block_ip("203.0.113.7", "teste real")
    assert fake_backend.block_calls == ["203.0.113.7"]
