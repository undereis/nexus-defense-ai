"""Segredos nunca em log/auditoria — invariante que já vale (trava contra regressão).

O Control Plane redige os params antes de auditar (`core/redaction`). Estes testes
travam esse comportamento para que nenhuma futura mudança em auditoria/propagação de
identidade volte a vazar token/senha/chave na trilha.

Passa HOJE — é rede de segurança, não bypass.
"""

from core import control_plane as cp
from core import redaction
import database.db as db_module


def test_audit_masks_secret_params_in_hash_chain():
    req = cp.make_request(
        "block_ip",
        target="203.0.113.5",
        params={
            "password": "SenhaSuperSecreta123",
            "api_key": "sk-ant-DEADBEEF12345",
            "authorization": "Bearer tok_abc123456xyz",
            "ip": "203.0.113.5",  # não-sensível, pode aparecer
        },
    )
    cp.evaluate(req)  # audita "control_plane_decision" com os params REDIGIDOS

    with db_module.get_conn() as conn:
        rows = conn.execute(
            "SELECT detail FROM events WHERE event_type = 'control_plane_decision'"
        ).fetchall()
    assert rows, "a decisão do Control Plane não foi auditada"
    blob = " ".join(r[0] or "" for r in rows)

    for secret in ("SenhaSuperSecreta123", "sk-ant-DEADBEEF12345", "tok_abc123456xyz"):
        assert secret not in blob, f"segredo vazou na auditoria: {secret}"
    assert redaction.MASK in blob


def test_redact_kwargs_masks_by_sensitive_name():
    out = redaction.redact_kwargs(
        {"password": "x1234567", "api_key": "y9876543", "ip": "1.2.3.4"}
    )
    assert out["password"] == redaction.MASK
    assert out["api_key"] == redaction.MASK
    assert out["ip"] == "1.2.3.4"  # não-sensível preservado


def test_redact_free_text_patterns():
    out = redaction.redact("Authorization: Bearer abcdef123456 e api_key=SECRETVAL123")
    assert "abcdef123456" not in out
    assert "SECRETVAL123" not in out
    assert redaction.MASK in out
