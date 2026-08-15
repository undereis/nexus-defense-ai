"""Proteção em repouso para credenciais observadas pelos honeypots.

Os valores são criptografados com Fernet antes de entrar no SQLite. A chave
fica fora do banco, preferencialmente no Keychain, sob
``HONEYPOT_CREDENTIAL_KEY``. Sem uma chave válida, o sistema falha de forma
segura: registra apenas um marcador redigido e nunca persiste texto claro.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

ENCRYPTED_PREFIX = "fernet:v1:"
REDACTED_VALUE = "[redacted:no-credential-key]"
PROTECTED_VALUE = "[protected:credential-key-unavailable]"


def _fernet(key: str) -> Fernet | None:
    if not key:
        return None
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, TypeError):
        return None


def protect(value: str | None, key: str) -> str | None:
    """Criptografa ``value`` ou o redige quando a chave não está disponível."""
    if value is None:
        return None
    if value.startswith(ENCRYPTED_PREFIX) or value == REDACTED_VALUE:
        return value
    cipher = _fernet(key)
    if cipher is None:
        return REDACTED_VALUE
    token = cipher.encrypt(value.encode("utf-8")).decode("ascii")
    return ENCRYPTED_PREFIX + token


def reveal(value: str | None, key: str) -> str | None:
    """Descriptografa valores protegidos sem vazar legados em texto claro."""
    if value is None:
        return None
    if value == REDACTED_VALUE:
        return REDACTED_VALUE
    if not value.startswith(ENCRYPTED_PREFIX):
        return PROTECTED_VALUE
    cipher = _fernet(key)
    if cipher is None:
        return PROTECTED_VALUE
    try:
        return cipher.decrypt(value[len(ENCRYPTED_PREFIX):].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeError):
        return PROTECTED_VALUE


def is_protected(value: str | None) -> bool:
    return value is None or value == REDACTED_VALUE or value.startswith(ENCRYPTED_PREFIX)
