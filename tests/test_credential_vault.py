"""Credenciais de honeypot nunca devem repousar em texto claro."""

from core import credential_vault

TEST_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def test_round_trip_keeps_plaintext_out_of_storage():
    stored = credential_vault.protect("S3nh@F0rte!", TEST_KEY)

    assert stored.startswith(credential_vault.ENCRYPTED_PREFIX)
    assert "S3nh@F0rte!" not in stored
    assert credential_vault.reveal(stored, TEST_KEY) == "S3nh@F0rte!"


def test_missing_key_redacts_instead_of_storing_plaintext():
    stored = credential_vault.protect("admin123", "")

    assert stored == credential_vault.REDACTED_VALUE
    assert credential_vault.reveal(stored, "") == credential_vault.REDACTED_VALUE


def test_legacy_plaintext_is_never_returned_directly():
    assert credential_vault.reveal("legacy-secret", TEST_KEY) == credential_vault.PROTECTED_VALUE


def test_database_rows_are_encrypted_but_read_contract_is_preserved(tmp_path, monkeypatch):
    import database.db as db_module

    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "vault.db")
    monkeypatch.setattr(db_module, "HONEYPOT_CREDENTIAL_KEY", TEST_KEY)
    db_module.init_db()
    db_module.record_honeypot_credential("203.0.113.9", 22, "ssh", "root", "password")

    with db_module.get_conn() as conn:
        raw = conn.execute(
            "SELECT username, password FROM honeypot_credentials"
        ).fetchone()
    assert raw[0].startswith(credential_vault.ENCRYPTED_PREFIX)
    assert raw[1].startswith(credential_vault.ENCRYPTED_PREFIX)
    assert raw != ("root", "password")

    row = db_module.list_honeypot_credentials()[0]
    assert row[3:5] == ("root", "password")
