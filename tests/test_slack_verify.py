import hashlib
import hmac
import time

from tools.slack_verify import verify_signature

SECRET = "minha-chave-secreta"


def _sign(secret: str, timestamp: str, body: str) -> str:
    basestring = f"v0:{timestamp}:{body}".encode("utf-8")
    return "v0=" + hmac.new(secret.encode("utf-8"), basestring, hashlib.sha256).hexdigest()


def test_valid_signature_accepted():
    timestamp = str(int(time.time()))
    body = "text=oi&response_url=https://example.com"
    signature = _sign(SECRET, timestamp, body)
    assert verify_signature(SECRET, timestamp, body, signature) is True


def test_wrong_secret_rejected():
    timestamp = str(int(time.time()))
    body = "text=oi"
    signature = _sign("chave-errada", timestamp, body)
    assert verify_signature(SECRET, timestamp, body, signature) is False


def test_tampered_body_rejected():
    timestamp = str(int(time.time()))
    signature = _sign(SECRET, timestamp, "text=oi")
    assert verify_signature(SECRET, timestamp, "text=comando_malicioso", signature) is False


def test_old_timestamp_rejected_replay_protection():
    old_timestamp = str(int(time.time()) - 600)  # 10 minutos atrás
    body = "text=oi"
    signature = _sign(SECRET, old_timestamp, body)
    assert verify_signature(SECRET, old_timestamp, body, signature) is False


def test_missing_secret_rejected():
    timestamp = str(int(time.time()))
    body = "text=oi"
    signature = _sign(SECRET, timestamp, body)
    assert verify_signature("", timestamp, body, signature) is False


def test_missing_signature_rejected():
    timestamp = str(int(time.time()))
    assert verify_signature(SECRET, timestamp, "text=oi", "") is False


def test_malformed_timestamp_rejected():
    body = "text=oi"
    signature = _sign(SECRET, "nao-e-um-numero", body)
    assert verify_signature(SECRET, "nao-e-um-numero", body, signature) is False
