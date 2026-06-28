"""Testes da estatística robusta anti-envenenamento (Fase 7, item 2).

Três camadas:
  1. Funções puras de tools/robust_stats.py (mediana/MAD, z modificado).
  2. Integração do detector robusto em tools/anomaly.py e
     tools/client_baseline.py — em especial `poisoning_suspected`, que dispara
     quando só o robusto acusa (média arrastada por envenenamento lento).
  3. Relatórios de maturidade/cobertura dos 168 slots semanais (global e por
     cliente).

O ponto central: o detector robusto SÓ acrescenta detecção (is_anomaly =
clássico OU robusto) — nunca cega. A própria divergência entre os dois é o
sinal de envenenamento.
"""

from datetime import datetime, timezone

import pytest

import database.db as db_module
from tools import anomaly, client_baseline
from tools.robust_stats import median_mad, modified_z_score, robust_z

_FIXED_TIME = datetime(2026, 6, 26, 14, 0, tzinfo=timezone.utc)  # sexta 14h
_CIDR = "203.0.113.0/24"
_IN_A = "203.0.113.5"


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    db_module.init_db()
    yield


# ---------- 1. funções puras ----------

def test_median_mad_empty_is_zero():
    assert median_mad([]) == (0.0, 0.0)


def test_median_mad_basic():
    med, mad = median_mad([1, 2, 3, 4, 5])
    assert med == 3
    # desvios absolutos: [2,1,0,1,2] -> mediana 1
    assert mad == 1


def test_median_mad_resists_outlier():
    """A mediana mal se move com um outlier extremo — é o ponto da robustez."""
    med, _ = median_mad([10, 10, 10, 10, 10000])
    assert med == 10


def test_modified_z_zero_when_mad_zero():
    """MAD == 0 (baseline degenerada) deve devolver 0.0, deixando o caso para o
    detector clássico — nunca gerar falso positivo a partir de variância nula."""
    assert modified_z_score(999, 10, 0) == 0.0


def test_modified_z_scales_like_stdev():
    # 0.6745 * (x - med) / mad
    assert modified_z_score(20, 10, 5) == pytest.approx(0.6745 * 10 / 5)


def test_robust_z_shortcut_matches_components():
    values = [18, 22, 19, 21, 20]
    med, mad = median_mad(values)
    assert robust_z(200, values) == pytest.approx(modified_z_score(200, med, mad))


# ---------- 2a. integração global (anomaly.py) ----------

def test_global_robust_field_present_and_agrees_on_normal():
    for v in [18, 22, 19, 21, 20, 23, 17, 22, 20, 19]:
        anomaly.record_current_sample(v, v, _FIXED_TIME)
    r = anomaly.check_anomaly(21, _FIXED_TIME)
    assert r["is_anomaly"] is False
    assert r["classic_anomaly"] is False
    assert r["robust_anomaly"] is False
    assert r["poisoning_suspected"] is False
    assert "robust_z_score" in r and "median" in r and "mad" in r


def test_global_spike_flagged_by_both():
    for v in [18, 22, 19, 21, 20, 23, 17, 22, 20, 19]:
        anomaly.record_current_sample(v, v, _FIXED_TIME)
    r = anomaly.check_anomaly(200, _FIXED_TIME)
    assert r["is_anomaly"] is True
    # um pico óbvio é pego pelos dois detectores
    assert r["classic_anomaly"] is True
    assert r["robust_anomaly"] is True


def test_global_poisoning_detected_when_only_robust_fires():
    """Frog boiling: tráfego sobe devagar e arrasta a média. O clássico se cega
    (desvio inflado pela própria rampa), mas a mediana/MAD resiste — só o robusto
    acusa, e poisoning_suspected sinaliza o envenenamento."""
    # baseline já envenenada: a maioria gira em torno de ~10 (pouca dispersão),
    # mas algumas amostras altas inflaram média e desvio (clássico cego) sem
    # mover a mediana/MAD. Um valor modesto (60) fica muito acima da mediana
    # real, mas abaixo da média inflada — só o robusto enxerga.
    ramp = [8, 9, 10, 11, 12, 10, 9, 200, 210, 220, 230]
    for v in ramp:
        anomaly.record_current_sample(v, v, _FIXED_TIME)
    r = anomaly.check_anomaly(60, _FIXED_TIME)
    assert r["classic_anomaly"] is False
    assert r["robust_anomaly"] is True
    assert r["poisoning_suspected"] is True
    assert r["is_anomaly"] is True  # OR garante que ainda dispara


def test_global_describe_warns_on_poisoning():
    ramp = [8, 9, 10, 11, 12, 10, 9, 200, 210, 220, 230]
    for v in ramp:
        anomaly.record_current_sample(v, v, _FIXED_TIME)
    text = anomaly.describe_anomaly_status(60, _FIXED_TIME)
    assert "ENVENENAMENTO" in text


# ---------- 2b. integração por cliente (client_baseline.py) ----------

def test_client_robust_agrees_on_normal():
    client_baseline.add_client_profile("xfiber-teste", _CIDR, "Cliente")
    for v in [18, 22, 19, 21, 20, 23, 17, 22, 20, 19]:
        db_module.record_client_traffic_sample(
            "xfiber-teste", _FIXED_TIME.hour, _FIXED_TIME.weekday(), v, 1
        )
    r = client_baseline.check_client_anomaly("xfiber-teste", 21, _FIXED_TIME)
    assert r["is_anomaly"] is False
    assert r["poisoning_suspected"] is False
    assert "robust_z_score" in r


def test_client_poisoning_detected():
    client_baseline.add_client_profile("xfiber-teste", _CIDR, "Cliente")
    ramp = [8, 9, 10, 11, 12, 10, 9, 200, 210, 220, 230]
    for v in ramp:
        db_module.record_client_traffic_sample(
            "xfiber-teste", _FIXED_TIME.hour, _FIXED_TIME.weekday(), v, 1
        )
    r = client_baseline.check_client_anomaly("xfiber-teste", 60, _FIXED_TIME)
    assert r["classic_anomaly"] is False
    assert r["robust_anomaly"] is True
    assert r["poisoning_suspected"] is True
    assert r["is_anomaly"] is True


# ---------- 3. relatórios de maturidade ----------

def test_global_maturity_blind_when_empty():
    text = anomaly.baseline_maturity_report()
    assert "0/168" in text
    assert "CEGA" in text


def test_global_maturity_counts_ready_slots():
    # slot A fica pronto (>=5), slot B fica imaturo (<5)
    for v in range(5):
        anomaly.record_current_sample(20, 20, _FIXED_TIME)
    other = datetime(2026, 6, 26, 3, 0, tzinfo=timezone.utc)  # mesma sexta, 3h
    for v in range(2):
        anomaly.record_current_sample(5, 5, other)
    text = anomaly.baseline_maturity_report()
    assert "Amostras coletadas: 7" in text
    assert "2/168" in text          # dois slots com algum dado
    assert "1/168" in text          # só um slot pronto (>=5)


def test_client_maturity_not_found():
    text = client_baseline.describe_client_baseline_maturity("nao-existe")
    assert "não encontrado" in text


def test_client_maturity_blind_when_empty():
    client_baseline.add_client_profile("xfiber-teste", _CIDR, "Cliente")
    text = client_baseline.describe_client_baseline_maturity("xfiber-teste")
    assert "0/168" in text
    assert "CEGA" in text


def test_client_maturity_counts_ready_slots():
    client_baseline.add_client_profile("xfiber-teste", _CIDR, "Cliente")
    for _ in range(5):
        db_module.record_client_traffic_sample(
            "xfiber-teste", _FIXED_TIME.hour, _FIXED_TIME.weekday(), 20, 1
        )
    for _ in range(2):
        db_module.record_client_traffic_sample(
            "xfiber-teste", 3, _FIXED_TIME.weekday(), 5, 1
        )
    text = client_baseline.describe_client_baseline_maturity("xfiber-teste")
    assert "Amostras: 7" in text
    assert "2/168" in text   # dois slots com dado
    assert "1/168" in text   # um pronto
