"""Testes da integração SIEM (Frente I — tools/siem.py)."""

import pytest
import requests

import database.db as db_module
from tools import siem


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    db_module.init_db()
    yield


class _Resp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("sem json")
        return self._payload


def _seed(n=3):
    for i in range(n):
        db_module.log_event("evt", f"10.0.0.{i}", f"detalhe {i}")


def _cfg(monkeypatch, mode="webhook", url="https://siem.x/in", token="tok"):
    monkeypatch.setattr(siem, "SIEM_MODE", mode)
    monkeypatch.setattr(siem, "SIEM_URL", url)
    monkeypatch.setattr(siem, "SIEM_TOKEN", token)


def test_off_does_nothing(monkeypatch):
    monkeypatch.setattr(siem, "SIEM_MODE", "off")

    def boom(*a, **k):
        raise AssertionError("não deveria postar com SIEM off")

    monkeypatch.setattr(siem.requests, "post", boom)
    assert "desligado" in siem.forward_new_events()


def test_webhook_forwards_and_advances(monkeypatch):
    _seed(3)
    _cfg(monkeypatch, mode="webhook")
    cap = {}

    def fake_post(url, **kw):
        cap["url"] = url
        cap["json"] = kw.get("json")
        cap["headers"] = kw.get("headers")
        return _Resp(200, {"ok": True})

    monkeypatch.setattr(siem.requests, "post", fake_post)
    out = siem.forward_new_events()
    assert "3 evento" in out
    assert cap["url"] == "https://siem.x/in"
    assert len(cap["json"]["events"]) == 3
    assert cap["headers"]["Authorization"] == "Bearer tok"
    # CP-SD Fase 6H: o disparo em si agora passa por cp.request_action, que
    # audita a decisão (control_plane_decision + control_plane_executed) na
    # MESMA tabela `events` que o SIEM varre — por isso a 2ª chamada não
    # encontra "nada novo", encontra os 2 registros de auditoria do próprio
    # disparo anterior. Comportamento novo e documentado, não um bug.
    second = siem.forward_new_events()
    assert "2 evento(s) enviados" in second


def test_elastic_bulk_format(monkeypatch):
    _seed(2)
    _cfg(monkeypatch, mode="elastic", url="https://es.x:9200", token="apikey")
    cap = {}

    def fake_post(url, **kw):
        cap["url"] = url
        cap["data"] = kw.get("data")
        cap["headers"] = kw.get("headers")
        return _Resp(200, {"errors": False})

    monkeypatch.setattr(siem.requests, "post", fake_post)
    out = siem.forward_new_events()
    assert "enviados (elastic)" in out
    assert cap["url"].endswith("/_bulk")
    assert '"index"' in cap["data"]  # linha de ação do bulk
    assert cap["headers"]["Authorization"] == "ApiKey apikey"


def test_splunk_hec_format(monkeypatch):
    _seed(1)
    _cfg(monkeypatch, mode="splunk",
         url="https://splunk.x:8088/services/collector/event", token="hec")
    cap = {}

    def fake_post(url, **kw):
        cap["headers"] = kw.get("headers")
        cap["data"] = kw.get("data")
        return _Resp(200, {"code": 0})

    monkeypatch.setattr(siem.requests, "post", fake_post)
    out = siem.forward_new_events()
    assert "splunk" in out
    assert cap["headers"]["Authorization"] == "Splunk hec"
    assert '"event"' in cap["data"]


def test_failure_keeps_cursor(monkeypatch):
    _seed(2)
    _cfg(monkeypatch, mode="webhook")
    monkeypatch.setattr(siem.requests, "post", lambda url, **kw: _Resp(500))
    out = siem.forward_new_events()
    assert "recusou" in out
    assert db_module.get_siem_cursor() == 0  # não avançou


def test_network_error_caught(monkeypatch):
    _seed(1)
    _cfg(monkeypatch, mode="webhook")

    def boom(url, **kw):
        raise requests.RequestException("down")

    monkeypatch.setattr(siem.requests, "post", boom)
    out = siem.forward_new_events()
    assert "falha" in out.lower()
    assert db_module.get_siem_cursor() == 0


def test_incremental_only_new(monkeypatch):
    _seed(2)
    _cfg(monkeypatch, mode="webhook")
    sent = []

    def fake_post(url, **kw):
        body = kw.get("json")
        sent.append(len(body["events"]) if body else 0)
        return _Resp(200, {"ok": True})

    monkeypatch.setattr(siem.requests, "post", fake_post)
    siem.forward_new_events()                 # envia os 2 iniciais
    db_module.log_event("evt", "10.0.0.9", "novo")
    # CP-SD Fase 6H: a 1ª chamada acima já gerou 2 eventos de auditoria do
    # próprio Control Plane (control_plane_decision + control_plane_executed)
    # na mesma tabela `events` — a 2ª chamada envia o evento manual "novo"
    # MAIS esses 2, não só o manual isolado.
    siem.forward_new_events()
    assert sent == [2, 3]


def test_describe_status(monkeypatch):
    _seed(2)
    _cfg(monkeypatch, mode="webhook")
    s = siem.describe_status()
    assert "modo=webhook" in s and "2 evento" in s
