"""Isolamento de rede via pfctl (macOS).

Usa uma tabela pf dedicada (`nexus_blocklist`) dentro de um anchor próprio
(`nexus_defense`), para nunca tocar nas regras de firewall existentes do
usuário. Requer privilégios de root — os comandos pfctl são executados
com `sudo` e podem pedir senha no terminal na primeira chamada.
"""

import ipaddress
import subprocess

from config import PF_ANCHOR_NAME
from database.db import record_blocked_ip, remove_blocked_ip

ANCHOR_FILE = f"/etc/pf.anchors/{PF_ANCHOR_NAME}"
PF_CONF = "/etc/pf.conf"
TABLE_NAME = "nexus_blocklist"

ANCHOR_RULES = f"table <{TABLE_NAME}> persist\nblock drop quick from <{TABLE_NAME}> to any\n"
PF_CONF_BLOCK = f'\nanchor "{PF_ANCHOR_NAME}"\nload anchor "{PF_ANCHOR_NAME}" from "{ANCHOR_FILE}"\n'


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def _validate_ip(ip: str) -> str:
    return str(ipaddress.ip_address(ip))


def setup_firewall() -> str:
    """Configura o anchor pf uma única vez. Idempotente. Requer sudo."""
    write_anchor = subprocess.run(
        ["sudo", "tee", ANCHOR_FILE], input=ANCHOR_RULES, capture_output=True, text=True
    )
    if write_anchor.returncode != 0:
        return f"Falha ao escrever anchor: {write_anchor.stderr}"

    pf_conf_check = _run(["sudo", "grep", "-q", PF_ANCHOR_NAME, PF_CONF])
    if pf_conf_check.returncode != 0:
        append = subprocess.run(
            ["sudo", "tee", "-a", PF_CONF], input=PF_CONF_BLOCK, capture_output=True, text=True
        )
        if append.returncode != 0:
            return f"Falha ao atualizar pf.conf: {append.stderr}"

    reload_result = _run(["sudo", "pfctl", "-f", PF_CONF])
    enable_result = _run(["sudo", "pfctl", "-e"])

    if reload_result.returncode != 0 and "already" not in reload_result.stderr.lower():
        return f"Falha ao recarregar pf: {reload_result.stderr}"

    return "Firewall (pf) configurado e ativo."


def block_ip(ip: str, reason: str = "") -> str:
    ip = _validate_ip(ip)
    result = _run(["sudo", "pfctl", "-t", TABLE_NAME, "-T", "add", ip])
    if result.returncode != 0:
        return f"Falha ao bloquear {ip}: {result.stderr.strip()}"
    record_blocked_ip(ip, reason)
    return f"IP {ip} isolado/bloqueado com sucesso."


def unblock_ip(ip: str) -> str:
    ip = _validate_ip(ip)
    result = _run(["sudo", "pfctl", "-t", TABLE_NAME, "-T", "delete", ip])
    if result.returncode != 0:
        return f"Falha ao desbloquear {ip}: {result.stderr.strip()}"
    remove_blocked_ip(ip)
    return f"IP {ip} desbloqueado."


def list_blocked() -> str:
    result = _run(["sudo", "pfctl", "-t", TABLE_NAME, "-T", "show"])
    if result.returncode != 0:
        return f"Falha ao listar bloqueios: {result.stderr.strip()}"
    return result.stdout.strip() or "Nenhum IP bloqueado atualmente."
