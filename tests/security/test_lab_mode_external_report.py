"""Risco crítico #1 (variação externa) — lab NÃO pode fazer chamada externa real.

`tools/threat_feeds.report_to_abuseipdb` reporta o IP ao AbuseIPDB (POST público que
contamina a reputação GLOBAL). Em modo lab/replay isso deveria virar no-op. HOJE ele
ignora o modo — por isso o teste de lab é xfail(strict=True).

Nenhuma chamada externa real acontece: o cliente HTTP é substituído por um FAKE, e a
chave é fake (não sai do processo). O teste força a chave preenchida DE PROPÓSITO para
exercitar a fronteira HTTP (senão a função retorna "não configurado" antes do POST e o
teste passaria por engano).
"""

import pytest

import tools.threat_feeds as threat_feeds
from core import operating_mode


class _FakeResp:
    def json(self):
        return {"data": {"abuseConfidenceScore": 42}}


class _FakeRequests:
    RequestException = Exception  # threat_feeds referencia requests.RequestException

    def __init__(self):
        self.post_calls: list = []

    def post(self, *a, **k):
        self.post_calls.append((a, k))
        return _FakeResp()


@pytest.fixture
def fake_requests(monkeypatch):
    fake = _FakeRequests()
    monkeypatch.setattr(threat_feeds, "requests", fake)
    # Força a chave preenchida para o fluxo chegar ao POST (fronteira sob teste).
    monkeypatch.setattr(threat_feeds, "ABUSEIPDB_API_KEY", "chave-de-teste-fake")
    return fake


@pytest.mark.xfail(strict=True, reason=(
    "BYPASS Fase 0: report_to_abuseipdb não consulta operating_mode; em LAB ele faz o "
    "POST externo (contamina a reputação global). A Fase A deve virar no-op em lab/replay."))
def test_lab_mode_abuseipdb_must_not_call_external(fake_requests):
    operating_mode.set_operating_mode("lab")
    threat_feeds.report_to_abuseipdb("203.0.113.5", [14], "teste")
    assert fake_requests.post_calls == []   # nenhuma chamada externa em lab


def test_real_mode_abuseipdb_calls_external(fake_requests):
    """Safety net (passa HOJE): em modo REAL, com chave, o report É enviado. A Fase A
    não pode quebrar o report legítimo em produção."""
    operating_mode.set_operating_mode("real")
    threat_feeds.report_to_abuseipdb("203.0.113.9", [14], "teste")
    assert len(fake_requests.post_calls) == 1
