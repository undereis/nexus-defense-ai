import importlib

import pytest


@pytest.fixture
def db(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_reconcile.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    import tools.reconcile as reconcile
    importlib.reload(reconcile)
    yield dbmod, reconcile


def test_no_drift_when_states_match(db, monkeypatch):
    dbmod, reconcile = db
    dbmod.record_blocked_ip("1.1.1.1", "teste")
    monkeypatch.setattr("tools.reconcile.firewall.get_actual_blocked_ips", lambda: {"1.1.1.1"})

    result = reconcile.check_and_reconcile(auto_reapply=True)
    assert result.checked is True
    assert result.has_drift is False
    assert result.missing == []


def test_detects_and_reapplies_missing_ip(db, monkeypatch):
    dbmod, reconcile = db
    dbmod.record_blocked_ip("2.2.2.2", "teste")
    monkeypatch.setattr("tools.reconcile.firewall.get_actual_blocked_ips", lambda: set())
    monkeypatch.setattr(
        "tools.reconcile.firewall.block_ip", lambda ip, reason: f"IP {ip} isolado/bloqueado com sucesso."
    )

    # CP-SD Fase 6R (endurecimento): a reaplicação só é autorizada sob a
    # identidade de serviço instalada pelo entrypoint automático (reconcile_loop).
    # Simulamos esse contexto — sem ele o Control Plane nega e vai para
    # reapply_errors (ver test_defense_subsystems_control_plane.py).
    from core import control_plane as cp
    from core import rbac
    with cp.principal_context(rbac.SERVICE_RECONCILE_PRINCIPAL):
        result = reconcile.check_and_reconcile(auto_reapply=True)
    assert result.has_drift is True
    assert result.missing == ["2.2.2.2"]
    assert result.reapplied == ["2.2.2.2"]
    assert result.reapply_errors == {}


def test_does_not_reapply_when_auto_reapply_false(db, monkeypatch):
    dbmod, reconcile = db
    dbmod.record_blocked_ip("3.3.3.3", "teste")
    monkeypatch.setattr("tools.reconcile.firewall.get_actual_blocked_ips", lambda: set())
    called = {"n": 0}
    monkeypatch.setattr(
        "tools.reconcile.firewall.block_ip", lambda ip, reason: called.update(n=called["n"] + 1)
    )

    result = reconcile.check_and_reconcile(auto_reapply=False)
    assert result.missing == ["3.3.3.3"]
    assert result.reapplied == []
    assert called["n"] == 0


def test_extra_ip_reported_but_not_removed(db, monkeypatch):
    dbmod, reconcile = db
    monkeypatch.setattr("tools.reconcile.firewall.get_actual_blocked_ips", lambda: {"9.9.9.9"})

    result = reconcile.check_and_reconcile(auto_reapply=True)
    assert result.extra == ["9.9.9.9"]
    assert result.has_drift is True


def test_returns_unchecked_when_firewall_unreachable(db, monkeypatch):
    dbmod, reconcile = db
    monkeypatch.setattr("tools.reconcile.firewall.get_actual_blocked_ips", lambda: None)

    result = reconcile.check_and_reconcile(auto_reapply=True)
    assert result.checked is False
    assert result.has_drift is False
    assert "verificar" in reconcile.describe(result)


def test_reapply_failure_is_reported(db, monkeypatch):
    dbmod, reconcile = db
    dbmod.record_blocked_ip("4.4.4.4", "teste")
    monkeypatch.setattr("tools.reconcile.firewall.get_actual_blocked_ips", lambda: set())
    monkeypatch.setattr(
        "tools.reconcile.firewall.block_ip", lambda ip, reason: "Falha ao bloquear: erro de teste"
    )

    # Contexto de serviço (entrypoint) para o executor de fato rodar e o
    # block_ip mockado devolver a falha — testando o caminho de FALHA de
    # bloqueio, não o de negação por identidade.
    from core import control_plane as cp
    from core import rbac
    with cp.principal_context(rbac.SERVICE_RECONCILE_PRINCIPAL):
        result = reconcile.check_and_reconcile(auto_reapply=True)
    assert result.reapplied == []
    assert "4.4.4.4" in result.reapply_errors
    description = reconcile.describe(result)
    assert "FALHA" in description
