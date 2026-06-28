"""Testes para tools/threshold_tuning.py — auto-ajuste de thresholds (Fase 7, item 4).

Foco nas travas de SEGURANÇA: bounded (piso/teto rígidos), passo limitado,
evidência mínima, operador no loop (confirm), e re-clamp na leitura. Afrouxar
um threshold pode cegar a detecção — estes testes garantem que não dá.
"""

import pytest

import database.db as db_module
from tools import client_risk, threshold_tuning


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    db_module.init_db()
    yield


def _feedback(label, n, alert_type="global_anomaly", scope="global"):
    for _ in range(n):
        threshold_tuning.record_feedback(alert_type, scope, label)


# ---- _clamp_z (trava definitiva) ----

def test_clamp_floor():
    assert threshold_tuning._clamp_z(0.1) == threshold_tuning._Z_FLOOR


def test_clamp_ceiling():
    assert threshold_tuning._clamp_z(99.0) == threshold_tuning._Z_CEILING


def test_clamp_passthrough():
    assert threshold_tuning._clamp_z(3.0) == 3.0


# ---- record_feedback ----

def test_record_feedback_valid():
    out = threshold_tuning.record_feedback("global_anomaly", "global", "fp")
    assert "registrado" in out.lower()


def test_record_feedback_invalid_label():
    out = threshold_tuning.record_feedback("global_anomaly", "global", "talvez")
    assert "inválido" in out.lower()
    # nada deve ter sido persistido
    counts = threshold_tuning._counts("global_anomaly", "global")
    assert counts["total"] == 0


# ---- effective_threshold ----

def test_effective_returns_base_when_no_override():
    assert threshold_tuning.effective_threshold("global_anomaly", "global") == \
        threshold_tuning.base_for("global_anomaly")


def test_effective_reclamps_stored_value_above_ceiling():
    # Mesmo um valor gravado acima do teto é corrigido na leitura (anti-cegueira).
    db_module.upsert_tuned_threshold("global_anomaly", "global", 99.0, 3.0)
    assert threshold_tuning.effective_threshold("global_anomaly", "global") == \
        threshold_tuning._Z_CEILING


# ---- propose_adjustment ----

def test_propose_insufficient_feedback():
    _feedback("fp", threshold_tuning._MIN_FEEDBACK - 1)
    p = threshold_tuning.propose_adjustment("global_anomaly", "global")
    assert p["actionable"] is False
    assert "insuficiente" in p["reason"].lower()


def test_propose_raise_on_false_positives():
    _feedback("fp", 5)
    p = threshold_tuning.propose_adjustment("global_anomaly", "global")
    assert p["actionable"] is True
    assert p["proposed"] == 3.0 + threshold_tuning._Z_STEP
    assert "subir" in p["direction"]


def test_propose_lower_on_missed():
    _feedback("missed", 5)
    p = threshold_tuning.propose_adjustment("global_anomaly", "global")
    assert p["actionable"] is True
    assert p["proposed"] == 3.0 - threshold_tuning._Z_STEP
    assert "baixar" in p["direction"]


def test_propose_stable_on_true_positives():
    _feedback("tp", 5)
    p = threshold_tuning.propose_adjustment("global_anomaly", "global")
    assert p["actionable"] is False
    assert "estável" in p["reason"].lower()


def test_propose_blocked_at_ceiling():
    # Já no teto: por mais falsos positivos, não sobe (anti-cegueira).
    db_module.upsert_tuned_threshold("global_anomaly", "global",
                                     threshold_tuning._Z_CEILING, 3.0)
    _feedback("fp", 5)
    p = threshold_tuning.propose_adjustment("global_anomaly", "global")
    assert p["actionable"] is False
    assert "teto" in p["reason"].lower()


def test_propose_blocked_at_floor():
    db_module.upsert_tuned_threshold("global_anomaly", "global",
                                     threshold_tuning._Z_FLOOR, 3.0)
    _feedback("missed", 5)
    p = threshold_tuning.propose_adjustment("global_anomaly", "global")
    assert p["actionable"] is False
    assert "piso" in p["reason"].lower()


# ---- apply_adjustment (operador no loop) ----

def test_apply_without_confirm_does_not_change():
    _feedback("fp", 5)
    out = threshold_tuning.apply_adjustment("global_anomaly", "global")
    assert "proposta" in out.lower()
    # não aplicado: efetivo continua no base
    assert threshold_tuning.effective_threshold("global_anomaly", "global") == 3.0


def test_apply_with_confirm_changes():
    _feedback("fp", 5)
    out = threshold_tuning.apply_adjustment("global_anomaly", "global", confirm=True)
    assert "ajustado" in out.lower()
    assert threshold_tuning.effective_threshold("global_anomaly", "global") == 3.5


def test_apply_with_toggle_changes(monkeypatch):
    monkeypatch.setattr(threshold_tuning, "ALLOW_THRESHOLD_AUTOTUNE", True)
    _feedback("fp", 5)
    out = threshold_tuning.apply_adjustment("global_anomaly", "global")
    assert "ajustado" in out.lower()
    assert threshold_tuning.effective_threshold("global_anomaly", "global") == 3.5


def test_apply_not_actionable():
    _feedback("tp", 5)
    out = threshold_tuning.apply_adjustment("global_anomaly", "global", confirm=True)
    assert "nada a aplicar" in out.lower()
    assert threshold_tuning.effective_threshold("global_anomaly", "global") == 3.0


def test_apply_never_exceeds_ceiling_over_repeated_runs():
    # Aplicar repetidamente nunca leva acima do teto.
    for _ in range(20):
        _feedback("fp", 5)
        threshold_tuning.apply_adjustment("global_anomaly", "global", confirm=True)
    assert threshold_tuning.effective_threshold("global_anomaly", "global") <= \
        threshold_tuning._Z_CEILING


# ---- reset ----

def test_reset_reverts_to_base():
    _feedback("fp", 5)
    threshold_tuning.apply_adjustment("global_anomaly", "global", confirm=True)
    assert threshold_tuning.effective_threshold("global_anomaly", "global") == 3.5
    out = threshold_tuning.reset_threshold("global_anomaly", "global")
    assert "revertido" in out.lower()
    assert threshold_tuning.effective_threshold("global_anomaly", "global") == 3.0


def test_reset_when_nothing_tuned():
    out = threshold_tuning.reset_threshold("global_anomaly", "global")
    assert "nenhum" in out.lower()


# ---- relatórios ----

def test_describe_tuning_text():
    _feedback("fp", 5)
    out = threshold_tuning.describe_tuning("global_anomaly", "global")
    assert "SUGESTÃO" in out
    assert "falso" in out.lower()


def test_overview_empty():
    out = threshold_tuning.tuning_overview()
    assert "nenhum" in out.lower()


def test_overview_lists_tuned():
    _feedback("fp", 5)
    threshold_tuning.apply_adjustment("global_anomaly", "global", confirm=True)
    out = threshold_tuning.tuning_overview()
    assert "global_anomaly/global" in out
    assert "3.5" in out


# ---- composição com o modelo de risco por cliente (item 3 + item 4) ----

def test_client_risk_uses_learned_base():
    client_risk.list_client_profiles  # módulo carregado
    db_module.add_client_profile("cli-x", "203.0.113.0/24", "")
    # sem sinais de risco => tier baixo => delta 0; sem tuning => base 3.0
    assert client_risk.adjusted_z_threshold("cli-x") == 3.0
    # aprende a subir o threshold daquele cliente por falsos positivos
    _feedback("fp", 5, alert_type="client_anomaly", scope="cli-x")
    threshold_tuning.apply_adjustment("client_anomaly", "cli-x", confirm=True)
    # agora o base aprendido (3.5) é usado, delta de risco 0 => 3.5
    assert client_risk.adjusted_z_threshold("cli-x") == 3.5
