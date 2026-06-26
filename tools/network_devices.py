"""Gestão multi-vendor de dispositivos de rede e servidores via SSH.

Unifica Linux, Cisco IOS, Huawei VRP e Ubiquiti EdgeOS/UniFi sob uma
única tool: a diferença entre fabricantes é só a sintaxe de comando
(show vs display, systemctl vs /etc/init.d, etc), então em vez de um
módulo dedicado por vendor, isto é um executor SSH com duas listas por
vendor — comandos de leitura (seguros, executam direto) e o resto
(qualquer coisa que não bate com a lista de leitura, que é tratado como
escrita/configuração e passa pelo gate de confirmação de tools/risk.py,
igual já fazemos com o Mikrotik).

Mikrotik tem um módulo dedicado (tools/mikrotik.py) porque usa a API
nativa RouterOS, não CLI via SSH — mais robusto que parsear texto.
Para os outros vendors, CLI via SSH é o jeito real que se administra
esse hardware no dia a dia, então é o caminho certo aqui.

NUNCA VALIDADO CONTRA HARDWARE REAL — Linux, Cisco, Huawei e Ubiquiti
físicos/virtuais ainda não estão disponíveis neste ambiente. Cobertura
hoje é só via mock. Antes de confiar em produção, valide ao menos os
comandos de leitura manualmente contra um dispositivo real de cada
vendor.
"""

import re
import subprocess

from config import SSH_KEY_PATH, SSH_USER
from database.db import log_event
from tools.access import _validate_host

VENDORS = ("linux", "cisco_ios", "huawei_vrp", "ubiquiti_edgeos")

# Comandos de leitura/diagnóstico considerados seguros por vendor —
# executam direto, sem passar pelo gate de confirmação. Qualquer coisa
# fora dessas listas é tratada como escrita/configuração.
_SAFE_READ_PATTERNS: dict[str, list[str]] = {
    "linux": [
        r"^uptime$", r"^uname -a$", r"^whoami$", r"^id$", r"^df -h$", r"^free -h$",
        r"^ps aux$", r"^ip (a|addr|route|r)( show)?$", r"^ss -tulpn$",
        r"^systemctl status [\w@.-]+$", r"^journalctl -u [\w@.-]+ -n \d+$",
        r"^cat /etc/os-release$", r"^hostname$",
    ],
    "cisco_ios": [
        r"^show (version|interfaces?|ip interface brief|running-config|ip route|vlan|arp|cdp neighbors?|mac address-table|users|clock)( .*)?$",
        r"^terminal length 0$",
    ],
    "huawei_vrp": [
        r"^display (version|interface|ip interface brief|current-configuration|ip routing-table|vlan|arp|lldp neighbor|mac-address|users|clock)( .*)?$",
    ],
    "ubiquiti_edgeos": [
        r"^show (interfaces|ip route|configuration|version|system|users)( .*)?$",
        r"^cat /etc/os-release$", r"^uptime$",
    ],
}

_COMPILED_SAFE_PATTERNS = {
    vendor: [re.compile(p) for p in patterns] for vendor, patterns in _SAFE_READ_PATTERNS.items()
}


def is_safe_read(vendor: str, command: str) -> bool:
    patterns = _COMPILED_SAFE_PATTERNS.get(vendor, [])
    return any(p.match(command.strip()) for p in patterns)


def _raw_ssh(host: str, command: str, user: str = "", port: int = 22) -> str:
    """Executa um comando via SSH sem nenhuma checagem de allowlist — só
    deve ser chamado depois que o caller (run_command ou o gate de
    confirmação) já decidiu que o comando pode rodar."""
    host = _validate_host(host)
    ssh_user = user or SSH_USER
    if not ssh_user:
        return "Nenhum usuário SSH configurado. Defina SSH_USER no .env ou informe o parâmetro 'user'."
    if not SSH_KEY_PATH:
        return "Nenhuma chave SSH configurada. Defina SSH_KEY_PATH no .env."

    cmd = [
        "ssh", "-i", SSH_KEY_PATH,
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        "-p", str(port),
        f"{ssh_user}@{host}",
        command,
    ]
    log_event("network_device_command", host, f"user={ssh_user} command={command!r}", action_taken="executando")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        log_event("network_device_command", host, f"command={command!r}", action_taken="timeout")
        return f"Comando excedeu 60s e foi interrompido: {command}"

    log_event(
        "network_device_command", host,
        f"command={command!r} returncode={result.returncode}", action_taken="concluido",
    )
    if result.returncode != 0:
        return f"Comando falhou (exit {result.returncode}):\n{result.stderr.strip() or result.stdout.strip()}"
    return result.stdout.strip() or "(comando executado sem saída)"


def run_read_command(vendor: str, host: str, command: str, user: str = "", port: int = 22) -> str:
    """Executa um comando de leitura/diagnóstico já validado como seguro
    para o vendor. Chamadores devem checar is_safe_read() antes (a tool do
    agente faz isso e devolve erro claro se não for seguro)."""
    if vendor not in VENDORS:
        return f"Vendor desconhecido: {vendor!r}. Suportados: {', '.join(VENDORS)}."
    if not is_safe_read(vendor, command):
        return (
            f"'{command}' não está na lista de comandos de leitura seguros para {vendor}. "
            "Isso deveria ter passado pelo gate de confirmação em vez de chamar leitura direta."
        )
    return _raw_ssh(host, command, user, port)
