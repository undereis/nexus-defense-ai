"""Testes para tools/client_baseline.py — baseline de tráfego por cliente."""

from datetime import datetime, timezone

import pytest

from tools import client_baseline


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    import database.db as db_module
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    db_module.init_db()
    yield


# ---- perfis de cliente ----

def test_add_client_profile_returns_success():
    result = client_baseline.add_client_profile("cliente1", "10.0.0.0/24", "Test")
    assert "cliente1" in result


def test_add_client_invalid_cidr():
    result = client_baseline.add_client_profile("cliente1", "999.0.0.0/24")
    assert "inválido" in result.lower() or "CIDR" in result


def test_list_clients_empty():
    result = client_baseline.list_client_profiles()
    assert "nenhum" in result.lower()


def test_list_clients_shows_registered():
    client_baseline.add_client_profile("xfiber-abc", "192.168.1.0/24", "Empresa ABC")
    result = client_baseline.list_client_profiles()
    assert "xfiber-abc" in result
    assert "192.168.1.0/24" in result


def test_remove_client():
    client_baseline.add_client_profile("temp", "10.1.0.0/24")
    client_baseline.remove_client_profile("temp")
    result = client_baseline.list_client_profiles()
    assert "temp" not in result


# ---- mapeamento IP → cliente ----

def test_ip_to_client_found():
    client_baseline.add_client_profile("empresa-x", "10.5.0.0/16", "X")
    assert client_baseline._ip_to_client("10.5.100.1") == "empresa-x"


def test_ip_to_client_not_found():
    client_baseline.add_client_profile("empresa-x", "10.5.0.0/16", "X")
    assert client_baseline._ip_to_client("192.168.1.1") is None


def test_ip_to_client_invalid_ip():
    assert client_baseline._ip_to_client("not-an-ip") is None


# ---- record_all_client_samples ----

def test_record_samples_maps_ips_to_clients():
    client_baseline.add_client_profile("c1", "10.0.0.0/24")
    client_baseline.add_client_profile("c2", "10.0.1.0/24")
    counts = {"10.0.0.1": 5, "10.0.0.2": 3, "10.0.1.1": 10}
    now = datetime(2025, 1, 1, 14, 0, 0, tzinfo=timezone.utc)
    client_baseline.record_all_client_samples(counts, now)
    # Apenas verifica que não lança exceção — as amostras foram gravadas
    result = client_baseline.describe_all_client_baselines()
    assert "c1" in result
    assert "c2" in result


def test_record_samples_ignores_unmapped_ips():
    counts = {"172.16.0.1": 100}
    client_baseline.record_all_client_samples(counts)
    # Sem cliente cadastrado, não deve lançar exceção


# ---- baseline insuficiente ----

def test_check_anomaly_insufficient_samples():
    client_baseline.add_client_profile("c1", "10.0.0.0/24")
    result = client_baseline.check_client_anomaly("c1", 50)
    assert result["is_anomaly"] is False
    assert result["samples_used"] == 0


def test_describe_anomaly_status_insufficient():
    client_baseline.add_client_profile("c1", "10.0.0.0/24", "Empresa")
    result = client_baseline.describe_client_anomaly_status("c1", 50)
    assert "baseline insuficiente" in result.lower() or "baseline" in result.lower()


def test_describe_anomaly_unknown_client():
    result = client_baseline.describe_client_anomaly_status("nao-existe", 50)
    assert "não encontrado" in result.lower()


# ---- detecção de anomalia com baseline suficiente ----

def _seed_samples(client_id: str, hour: int, dow: int, values: list[int]):
    from database.db import record_client_traffic_sample
    for v in values:
        record_client_traffic_sample(client_id, hour, dow, v, 1)


def test_normal_traffic_not_anomaly():
    client_baseline.add_client_profile("c1", "10.0.0.0/24")
    _seed_samples("c1", 10, 1, [100, 102, 98, 101, 99, 100])
    now = datetime(2025, 1, 7, 10, 0, tzinfo=timezone.utc)  # hora 10, terça
    result = client_baseline.check_client_anomaly("c1", 101, now)
    assert result["is_anomaly"] is False
    assert result["samples_used"] >= 5


def test_anomalous_traffic_detected():
    client_baseline.add_client_profile("c2", "10.0.1.0/24")
    _seed_samples("c2", 3, 0, [50, 52, 48, 51, 49, 50])
    now = datetime(2025, 1, 6, 3, 0, tzinfo=timezone.utc)  # hora 3, segunda
    result = client_baseline.check_client_anomaly("c2", 1000, now)
    assert result["is_anomaly"] is True
    assert result["z_score"] > 3.0


def test_check_all_client_anomalies_returns_only_anomalous():
    client_baseline.add_client_profile("ok", "10.0.0.0/24")
    client_baseline.add_client_profile("bad", "10.0.1.0/24")
    _seed_samples("ok", 10, 2, [100, 102, 98, 101, 99, 100])
    _seed_samples("bad", 10, 2, [50, 52, 48, 51, 49, 50])
    now = datetime(2025, 1, 8, 10, 0, tzinfo=timezone.utc)  # hora 10, quarta
    counts = {"10.0.0.5": 101, "10.0.1.5": 5000}
    anomalies = client_baseline.check_all_client_anomalies(counts, now)
    ids = [a["client_id"] for a in anomalies]
    assert "bad" in ids
    assert "ok" not in ids


def test_describe_all_client_baselines_empty():
    result = client_baseline.describe_all_client_baselines()
    assert "nenhum" in result.lower()


def test_describe_all_client_baselines_shows_stats():
    client_baseline.add_client_profile("c1", "10.0.0.0/24", "Test")
    now = datetime.now(timezone.utc)
    _seed_samples("c1", now.hour, now.weekday(), [200, 205, 195, 202, 198, 201])
    result = client_baseline.describe_all_client_baselines()
    assert "c1" in result
    assert "média" in result or "=" in result
