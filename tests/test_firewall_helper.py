from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest.mock import patch

import pytest

from tools.firewall_backends import pf

HELPER_PATH = Path(__file__).parents[1] / "deploy" / "nexus_firewall_helper.py"
SPEC = importlib.util.spec_from_file_location("nexus_firewall_helper", HELPER_PATH)
assert SPEC and SPEC.loader
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


def test_helper_builds_only_fixed_pfctl_command() -> None:
    assert helper.build_command(["block", "192.0.2.7"]) == [
        "/sbin/pfctl",
        "-a",
        "nexus_defense",
        "-t",
        "nexus_blocklist",
        "-T",
        "add",
        "192.0.2.7",
    ]


def test_helper_normalizes_cidr() -> None:
    assert helper.build_command(["block", "192.0.2.42/24"])[-1] == "192.0.2.0/24"


@pytest.mark.parametrize(
    "args",
    [
        ["block"],
        ["list", "192.0.2.1"],
        ["block", "192.0.2.1", "extra"],
        ["block", "192.0.2.1; id"],
        ["shell", "id"],
    ],
)
def test_helper_rejects_invalid_or_injectable_input(args: list[str]) -> None:
    with pytest.raises(ValueError):
        helper.build_command(args)


def test_pf_backend_uses_only_installed_helper() -> None:
    with patch.object(pf, "_run") as run:
        pf.block("198.51.100.8")
    run.assert_called_once_with(
        ["sudo", "/usr/local/libexec/nexus-firewall", "block", "198.51.100.8"]
    )
