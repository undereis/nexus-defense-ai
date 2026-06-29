"""Testes do simulador de tráfego sintético (Frente G)."""

from datetime import datetime, timezone

import pytest

import database.db as db_module
from tools import anomaly, client_baseline, traffic_sim

_NOW = datetime(2026, 6, 26, 14, 0, tzinfo=timezone.utc)  # sexta 14h


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    db_module.init_db()
    yield


def test_simulate_fills_all_weekly_slots():
    summary = traffic_sim.simulate_baseline(weeks=6, now=_NOW)
    assert summary["global_samples"] == 6 * 7 * 24  # 1008
    rep = anomaly.baseline_maturity_report()
    assert "168/168" in rep  # todos os slots prontos (>=5 amostras)


def test_diurnal_curve_peaks_in_evening():
    # 19h (pico) deve esperar mais conexões que 3h (madrugada)
    assert traffic_sim.expected_connections(19, 300) > traffic_sim.expected_connections(3, 300)


def test_spike_detected_after_simulation():
    traffic_sim.simulate_baseline(weeks=6, now=_NOW)
    r = anomaly.check_anomaly(5000, _NOW)  # muito acima do pico (~300)
    assert r["is_anomaly"] is True


def test_normal_value_not_flagged_after_simulation():
    traffic_sim.simulate_baseline(weeks=6, now=_NOW, seed=1)
    # valor próximo do esperado para o slot não deve disparar
    expected = int(traffic_sim.expected_connections(_NOW.hour, 300))
    r = anomaly.check_anomaly(expected, _NOW)
    assert r["is_anomaly"] is False


def test_client_baseline_simulated_and_detects():
    traffic_sim.simulate_baseline(weeks=6, clients=[("c1", "203.0.113.0/24")], now=_NOW)
    r = client_baseline.check_client_anomaly("c1", 99999, _NOW)
    assert r["is_anomaly"] is True


def test_describe_simulation_reports_before_after():
    text = traffic_sim.describe_simulation(weeks=6, now=_NOW)
    assert "ANTES:" in text and "DEPOIS:" in text
    assert "DETECTADO" in text  # demo de pico pega
