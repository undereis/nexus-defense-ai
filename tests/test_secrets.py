"""Segredos com Keychain do macOS + fallback .env (Fase 1) — core/secrets.py.

Hermético: NUNCA toca o Keychain real. Sob pytest o backend cai para 'env' por
padrão; os testes do caminho 'keychain' injetam um keyring FALSO (in-memory) via
monkeypatch object-form.
"""

import pytest

from core import secrets


class FakeKeyring:
    """Keyring in-memory que imita a API do módulo `keyring`."""

    def __init__(self):
        self.store: dict[tuple[str, str], str] = {}
        self.raise_on_get = False

    # `_keyring()` chama .get_keyring() e olha o class name (não pode ser fail/null)
    def get_keyring(self):
        return self

    def get_password(self, service, name):
        if self.raise_on_get:
            raise RuntimeError("keychain travado")
        return self.store.get((service, name))

    def set_password(self, service, name, value):
        self.store[(service, name)] = value

    def delete_password(self, service, name):
        if (service, name) in self.store:
            del self.store[(service, name)]
        else:
            raise RuntimeError("item ausente")


@pytest.fixture
def fake_kc(monkeypatch):
    """Injeta um keyring falso e força o backend 'keychain'."""
    fake = FakeKeyring()
    monkeypatch.setattr(secrets, "_keyring", lambda: fake)
    monkeypatch.setenv("NEXUS_SECRETS_BACKEND", "keychain")
    return fake


# ---------------- backend / hermeticidade ----------------

def test_backend_defaults_to_env_under_pytest(monkeypatch):
    monkeypatch.delenv("NEXUS_SECRETS_BACKEND", raising=False)
    # Sob pytest, 'auto' -> 'env' (não toca o Keychain real).
    assert secrets.resolve_backend() == "env"


def test_backend_env_override(monkeypatch, fake_kc):
    # Mesmo com keychain disponível, 'env' explícito vence.
    monkeypatch.setenv("NEXUS_SECRETS_BACKEND", "env")
    assert secrets.resolve_backend() == "env"


def test_backend_keychain_when_available(fake_kc):
    assert secrets.resolve_backend() == "keychain"
    assert secrets.keychain_available() is True


# ---------------- get_secret ----------------

def test_get_secret_falls_back_to_env(monkeypatch):
    monkeypatch.setenv("NEXUS_SECRETS_BACKEND", "env")
    monkeypatch.setenv("ALGUM_SEGREDO", "valor-do-env")
    assert secrets.get_secret("ALGUM_SEGREDO") == "valor-do-env"


def test_get_secret_default_when_absent(monkeypatch):
    monkeypatch.setenv("NEXUS_SECRETS_BACKEND", "env")
    monkeypatch.delenv("NAO_EXISTE_XYZ", raising=False)
    assert secrets.get_secret("NAO_EXISTE_XYZ", "padrao") == "padrao"


def test_get_secret_keychain_first(monkeypatch, fake_kc):
    fake_kc.store[(secrets.SERVICE, "TESTE")] = "valor-do-keychain"
    monkeypatch.setenv("TESTE", "valor-do-env")  # keychain deve VENCER
    assert secrets.get_secret("TESTE") == "valor-do-keychain"


def test_get_secret_keychain_empty_falls_back_to_env(monkeypatch, fake_kc):
    # Sem item no keychain -> usa env (não trata "" do keychain como válido).
    monkeypatch.setenv("TESTE2", "valor-do-env")
    assert secrets.get_secret("TESTE2") == "valor-do-env"


def test_get_secret_failsafe_on_keychain_error(monkeypatch):
    # Se o acesso ao keychain LEVANTA, get_secret cai no env sem propagar.
    monkeypatch.setenv("NEXUS_SECRETS_BACKEND", "keychain")
    monkeypatch.setattr(secrets, "_keyring", lambda: object())  # backend "presente"

    def boom(_name):
        raise RuntimeError("falha de acesso")

    monkeypatch.setattr(secrets, "_keychain_get", boom)
    monkeypatch.setenv("SEG_FAILSAFE", "valor-do-env")
    assert secrets.get_secret("SEG_FAILSAFE") == "valor-do-env"


# ---------------- set / delete ----------------

def test_set_and_delete_secret(fake_kc):
    assert secrets.set_secret("MIKROTIK_PASSWORD", "s3nha") is True
    assert fake_kc.store[(secrets.SERVICE, "MIKROTIK_PASSWORD")] == "s3nha"
    assert secrets.get_secret("MIKROTIK_PASSWORD") == "s3nha"
    assert secrets.delete_secret("MIKROTIK_PASSWORD") is True
    assert (secrets.SERVICE, "MIKROTIK_PASSWORD") not in fake_kc.store


def test_set_delete_return_false_without_keyring(monkeypatch):
    monkeypatch.setattr(secrets, "_keyring", lambda: None)
    assert secrets.set_secret("X", "y") is False
    assert secrets.delete_secret("X") is False


def test_delete_missing_item_returns_false(fake_kc):
    # delete de item ausente: delete_password levanta -> fail-safe -> False.
    assert secrets.delete_secret("NAO_ESTA_LA") is False


# ---------------- source / status ----------------

def test_secret_source(monkeypatch, fake_kc):
    fake_kc.store[(secrets.SERVICE, "AUDIT_HMAC_SECRET")] = "hmac"
    assert secrets.secret_source("AUDIT_HMAC_SECRET") == "keychain"
    monkeypatch.setenv("NEXUS_SECRETS_BACKEND", "env")
    monkeypatch.setenv("SIEM_TOKEN", "tok")
    assert secrets.secret_source("SIEM_TOKEN") == "env"
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    assert secrets.secret_source("SHODAN_API_KEY") == "ausente"


def test_secret_status_shape_no_values(monkeypatch, fake_kc):
    fake_kc.store[(secrets.SERVICE, "TELEGRAM_BOT_TOKEN")] = "123:ABCsupersecret"
    st = secrets.secret_status()
    assert {r["name"] for r in st} == set(secrets.SECRET_ENV_NAMES)
    for row in st:
        assert set(row.keys()) == {"name", "source", "present"}
        # NUNCA o valor no status.
        assert "123:ABCsupersecret" not in str(row)
    tg = next(r for r in st if r["name"] == "TELEGRAM_BOT_TOKEN")
    assert tg["source"] == "keychain" and tg["present"] is True


# ---------------- integração com config e a tool ----------------

def test_config_uses_get_secret():
    import config
    assert config._secret is secrets.get_secret


def test_secret_status_tool_runs():
    from agents.nexus_agent import secret_status_report
    out = secret_status_report.invoke({})
    assert "Backend de segredos" in out and "Keychain" in out
