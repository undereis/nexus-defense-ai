"""Risco crítico #2 (isolamento) — actor/role de uma execução não vaza para outra.

Hoje a identidade é passada como PARÂMETRO explícito em `make_request` (sem estado
global), então não há vazamento. Estes testes travam essa invariante ANTES da Fase B,
que vai introduzir propagação automática (provavelmente via ContextVar): se a
implementação futura usar estado global/compartilhado em vez de isolado por execução,
o teste de concorrência abaixo pega o vazamento.

Usa `policy_engine.evaluate` (função pura, sem escrita no DB) no laço concorrente para
não gerar contenção de escrita no SQLite.
"""

import threading

from core import control_plane as cp
from core import policy_engine
from core.models import Decision


def test_explicit_principals_do_not_leak_sequential():
    d_admin = policy_engine.evaluate(cp.make_request("block_ip", target="203.0.113.1", role="admin"))
    d_readonly = policy_engine.evaluate(cp.make_request("block_ip", target="203.0.113.1", role="readonly"))
    assert d_admin.decision is not Decision.DENY   # admin pode bloquear
    assert d_readonly.decision is Decision.DENY     # readonly não pode


def test_concurrent_principals_do_not_leak():
    """Duas 'execuções' concorrentes com papéis diferentes: cada uma deve enxergar o
    SEU papel em TODAS as iterações. Vazamento (papel de uma na outra) falha aqui."""
    results: dict[str, list] = {"admin": [], "readonly": []}
    barrier = threading.Barrier(2)

    def run(role: str):
        barrier.wait()  # maximiza a sobreposição das duas threads
        for _ in range(60):
            dec = policy_engine.evaluate(cp.make_request("block_ip", target="203.0.113.2", role=role))
            results[role].append(dec.decision)

    t_admin = threading.Thread(target=run, args=("admin",))
    t_readonly = threading.Thread(target=run, args=("readonly",))
    t_admin.start()
    t_readonly.start()
    t_admin.join()
    t_readonly.join()

    assert results["admin"] and all(d is not Decision.DENY for d in results["admin"])
    assert results["readonly"] and all(d is Decision.DENY for d in results["readonly"])
