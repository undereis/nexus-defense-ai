"""Assinatura HMAC da auditoria + export JSON (Prioridade 7) — core/audit_signing.py.

Garante que: a assinatura é no-op quando desligada; assina e verifica quando
ligada; detecta adulteração; e que NÃO toca a hash chain (verify_chain segue ok).
"""

import json

import pytest

import config
import database.db as db_module
from core import audit_signing
from tools import audit


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "test.db")
    db_module.init_db()
    yield


def test_disabled_is_noop(monkeypatch):
    monkeypatch.setattr(config, "AUDIT_HMAC_SECRET", "", raising=False)
    db_module.log_event("teste", None, "detalhe")
    assert audit_signing.sign_new_events() == 0
    res = audit_signing.verify_signatures()
    assert res.enabled is False
    assert "DESLIGADA" in audit_signing.describe(res)


def test_sign_and_verify(monkeypatch):
    monkeypatch.setattr(config, "AUDIT_HMAC_SECRET", "segredo-forte-de-teste", raising=False)
    for i in range(3):
        db_module.log_event("evt", None, f"detalhe {i}")
    signed = audit_signing.sign_new_events()
    assert signed == 3
    res = audit_signing.verify_signatures()
    assert res.enabled and res.intact and res.valid == 3 and res.checked == 3


def test_sign_is_idempotent(monkeypatch):
    monkeypatch.setattr(config, "AUDIT_HMAC_SECRET", "s3cr3t", raising=False)
    db_module.log_event("evt", None, "x")
    assert audit_signing.sign_new_events() == 1
    assert audit_signing.sign_new_events() == 0  # já assinado


def test_detects_tampering(monkeypatch):
    monkeypatch.setattr(config, "AUDIT_HMAC_SECRET", "s3cr3t", raising=False)
    db_module.log_event("evt", None, "original")
    audit_signing.sign_new_events()
    # adultera o entry_hash do evento depois de assinado
    with db_module.get_conn() as conn:
        conn.execute("UPDATE events SET entry_hash = 'deadbeef' WHERE id = 1")
    res = audit_signing.verify_signatures()
    assert not res.intact and 1 in res.mismatched


def test_wrong_secret_fails_verification(monkeypatch):
    monkeypatch.setattr(config, "AUDIT_HMAC_SECRET", "secret-A", raising=False)
    db_module.log_event("evt", None, "x")
    audit_signing.sign_new_events()
    monkeypatch.setattr(config, "AUDIT_HMAC_SECRET", "secret-B", raising=False)
    res = audit_signing.verify_signatures()
    assert not res.intact  # segredo trocado → assinaturas não conferem


def test_does_not_break_hash_chain(monkeypatch):
    monkeypatch.setattr(config, "AUDIT_HMAC_SECRET", "s3cr3t", raising=False)
    db_module.log_event("evt", None, "a")
    db_module.log_event("evt", None, "b")
    audit_signing.sign_new_events()
    chain = audit.verify_chain()
    assert chain.intact  # a assinatura é sidecar; a hash chain segue íntegra


def test_export_events_json(monkeypatch):
    monkeypatch.setattr(config, "AUDIT_HMAC_SECRET", "s3cr3t", raising=False)
    db_module.log_event("evt", "1.2.3.4", "detalhe")
    audit_signing.sign_new_events()
    data = json.loads(audit_signing.export_events_json())
    assert isinstance(data, list) and len(data) == 1
    row = data[0]
    assert row["event_type"] == "evt" and row["source_ip"] == "1.2.3.4"
    assert row["entry_hash"] and row["signature"]
