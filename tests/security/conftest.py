"""Fixtures e travas de segurança para os testes de caracterização (Fase 1A).

Estes testes formam a REDE DE SEGURANÇA antes de corrigir os bypasses da Fase 0.
Nada de produção é alterado aqui — só testes, mocks e fakes.

Garantias desta pasta (autouse):
- **DB temporário**: nunca toca `database/nexus.db` (só um SQLite em tmp_path).
- **Sem subprocess real**: pfctl/iptables/ping/etc. são bloqueados (AssertionError).
- **Sem rede externa real**: `requests.post/get` globais são bloqueados.
- **Sem notificação real**: `notify.send_notification` vira no-op.

Testes que precisam simular a fronteira de execução (backend de firewall, HTTP do
AbuseIPDB) injetam o próprio FAKE local — que registra a chamada sem efeito real.
"""

import subprocess

import pytest

import database.db as db_module


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    """DB isolado por teste — jamais o nexus.db real."""
    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "sec_test.db")
    db_module.init_db()
    yield


@pytest.fixture(autouse=True)
def block_real_side_effects(monkeypatch):
    """Backstop de segurança: qualquer efeito colateral real vira erro explícito.

    Os testes que legitimamente exercitam uma fronteira injetam seu próprio fake
    (backend de firewall, cliente HTTP do threat_feeds); este backstop pega
    apenas caminhos NÃO mockados, garantindo que nenhum teste toque o SO/rede
    por engano."""
    def _no_subprocess(*_a, **_k):
        raise AssertionError("subprocess real bloqueado no teste de segurança (Fase 1A)")

    monkeypatch.setattr(subprocess, "run", _no_subprocess)

    import requests

    def _no_net(*_a, **_k):
        raise AssertionError("chamada de rede real bloqueada no teste de segurança (Fase 1A)")

    monkeypatch.setattr(requests, "post", _no_net)
    monkeypatch.setattr(requests, "get", _no_net)

    from tools import notify

    monkeypatch.setattr(notify, "send_notification", lambda *a, **k: None)
    monkeypatch.setattr(notify, "is_configured", lambda: False)
    yield
