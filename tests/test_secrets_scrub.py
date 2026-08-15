from scripts import nexus_secrets


def test_scrub_env_only_blanks_values_already_in_keychain(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "NEXUS_API_TOKEN=secret-token\n"
        "ANTHROPIC_API_KEY=not-migrated\n"
        "NEXUS_OPERATING_MODE=lab\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        nexus_secrets.secrets,
        "_keychain_get",
        lambda name: "present" if name == "NEXUS_API_TOKEN" else None,
    )

    changed = nexus_secrets._scrub_env_file(
        ["NEXUS_API_TOKEN", "ANTHROPIC_API_KEY"], env_path
    )

    assert changed == ["NEXUS_API_TOKEN"]
    assert env_path.read_text(encoding="utf-8") == (
        "NEXUS_API_TOKEN=\n"
        "ANTHROPIC_API_KEY=not-migrated\n"
        "NEXUS_OPERATING_MODE=lab\n"
    )
    assert env_path.stat().st_mode & 0o777 == 0o600
