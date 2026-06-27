"""Testes para tools/anomaly.py — detecção de anomalia por baseline
estatística (z-score). Usa um banco isolado em tmp_path (não o real do
projeto), com timestamps fixos para controlar o slot hora/dia-da-semana."""

import importlib
from datetime import datetime, timezone

import pytest

_FIXED_TIME = datetime(2026, 6, 26, 14, 0, tzinfo=timezone.utc)  # sexta-feira 14h


@pytest.fixture
def anomaly_module(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_anomaly.db")
    import database.db as dbmod
    importlib.reload(dbmod)
    dbmod.init_db()

    import tools.anomaly as anomaly
    importlib.reload(anomaly)
    yield anomaly


def test_check_anomaly_without_baseline_reports_insufficient_data(anomaly_module):
    result = anomaly_module.check_anomaly(999, _FIXED_TIME)
    assert result["is_anomaly"] is False
    assert result["samples_used"] == 0


def test_check_anomaly_with_baseline_flags_normal_traffic_as_not_anomalous(anomaly_module):
    for v in [18, 22, 19, 21, 20, 23, 17, 22, 20, 19]:
        anomaly_module.record_current_sample(v, v, _FIXED_TIME)

    result = anomaly_module.check_anomaly(21, _FIXED_TIME)
    assert result["samples_used"] == 10
    assert result["is_anomaly"] is False


def test_check_anomaly_flags_large_spike_as_anomalous(anomaly_module):
    for v in [18, 22, 19, 21, 20, 23, 17, 22, 20, 19]:
        anomaly_module.record_current_sample(v, v, _FIXED_TIME)

    result = anomaly_module.check_anomaly(200, _FIXED_TIME)
    assert result["is_anomaly"] is True
    assert result["z_score"] > anomaly_module.DEFAULT_Z_SCORE_THRESHOLD


def test_baseline_is_isolated_per_hour_and_day_of_week(anomaly_module):
    """Amostras de um horário não devem contaminar a baseline de outro —
    sem isso, o z-score perde todo o sentido (3h da manhã vs 20h não são
    comparáveis)."""
    morning = datetime(2026, 6, 26, 3, 0, tzinfo=timezone.utc)
    evening = datetime(2026, 6, 26, 20, 0, tzinfo=timezone.utc)

    for v in [2, 3, 2, 3, 2]:
        anomaly_module.record_current_sample(v, v, morning)
    for v in [500, 520, 510, 505, 515]:
        anomaly_module.record_current_sample(v, v, evening)

    morning_result = anomaly_module.check_anomaly(3, morning)
    evening_result = anomaly_module.check_anomaly(510, evening)

    assert morning_result["mean"] < 10
    assert evening_result["mean"] > 400
    assert morning_result["is_anomaly"] is False
    assert evening_result["is_anomaly"] is False


def test_describe_anomaly_status_text_without_baseline(anomaly_module):
    text = anomaly_module.describe_anomaly_status(50, _FIXED_TIME)
    assert "Ainda não há baseline suficiente" in text


def test_describe_anomaly_status_text_with_baseline(anomaly_module):
    for v in [18, 22, 19, 21, 20]:
        anomaly_module.record_current_sample(v, v, _FIXED_TIME)
    text = anomaly_module.describe_anomaly_status(20, _FIXED_TIME)
    assert "dentro do padrão normal" in text or "ANOMALIA DETECTADA" in text
    assert "Z-score" in text
