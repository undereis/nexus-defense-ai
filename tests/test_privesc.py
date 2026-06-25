from tools.privesc import enumerate_privesc


def test_runs_all_checks_and_aggregates(monkeypatch):
    calls = []

    def fake_ssh_run_command(host, command, user=""):
        calls.append(command)
        return f"saída de {command}"

    monkeypatch.setattr("tools.privesc.access.ssh_run_command", fake_ssh_run_command)
    result = enumerate_privesc("1.2.3.4")

    assert "id" in calls
    assert "sudo -l" in calls
    assert len(calls) == 7
    assert "Usuário atual" in result
    assert "saída de id" in result


def test_propagates_per_check_errors_without_crashing(monkeypatch):
    monkeypatch.setattr(
        "tools.privesc.access.ssh_run_command",
        lambda host, command, user="": "Nenhum usuário SSH configurado.",
    )
    result = enumerate_privesc("1.2.3.4")
    assert "Nenhum usuário SSH configurado." in result
    assert "Permissões sudo" in result
