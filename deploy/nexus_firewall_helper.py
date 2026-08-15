#!/usr/bin/env python3
"""Root-owned, narrowly scoped pfctl gateway for Nexus Defense AI."""

from __future__ import annotations

import ipaddress
import subprocess
import sys

PFCTL = "/sbin/pfctl"
ANCHOR = "nexus_defense"
TABLES = {"block": "nexus_blocklist", "rate": "nexus_ratelist"}
ACTIONS = {
    "block": ("block", "add", True),
    "unblock": ("block", "delete", True),
    "list": ("block", "show", False),
    "rate-block": ("rate", "add", True),
    "rate-unblock": ("rate", "delete", True),
    "rate-list": ("rate", "show", False),
}


def normalize_target(value: str) -> str:
    """Return a canonical IP or CIDR and reject all other input."""
    try:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError("target must be a valid IP address or CIDR") from exc


def build_command(argv: list[str]) -> list[str]:
    if not argv or argv[0] not in ACTIONS:
        raise ValueError("unsupported action")
    table_key, operation, needs_target = ACTIONS[argv[0]]
    expected = 2 if needs_target else 1
    if len(argv) != expected:
        raise ValueError("invalid argument count")
    command = [PFCTL, "-a", ANCHOR, "-t", TABLES[table_key], "-T", operation]
    if needs_target:
        command.append(normalize_target(argv[1]))
    return command


def main() -> int:
    try:
        command = build_command(sys.argv[1:])
    except ValueError as exc:
        print(f"nexus-firewall: {exc}", file=sys.stderr)
        return 2
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
