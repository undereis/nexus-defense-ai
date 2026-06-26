"""Backend de isolamento via pfctl (macOS).

Usa uma tabela pf dedicada (`nexus_blocklist`) dentro de um anchor próprio
(`nexus_defense`), para nunca tocar nas regras de firewall existentes do
usuário. Requer privilégios de root — os comandos pfctl são executados
com `sudo` e podem pedir senha no terminal na primeira chamada.
"""

import subprocess

from config import PF_ANCHOR_NAME

ANCHOR_FILE = f"/etc/pf.anchors/{PF_ANCHOR_NAME}"
PF_CONF = "/etc/pf.conf"
TABLE_NAME = "nexus_blocklist"

ANCHOR_RULES = f"table <{TABLE_NAME}> persist\nblock drop quick from <{TABLE_NAME}> to any\n"
PF_CONF_BLOCK = f'\nanchor "{PF_ANCHOR_NAME}"\nload anchor "{PF_ANCHOR_NAME}" from "{ANCHOR_FILE}"\n'


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def setup() -> str:
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
    _run(["sudo", "pfctl", "-e"])

    # "pfctl -f" sempre imprime o aviso inofensivo de ALTQ no stderr no macOS;
    # o que importa é se a tabela do nosso anchor de fato carregou no kernel.
    if reload_result.returncode != 0:
        return f"Falha ao recarregar pf: {reload_result.stderr.strip()}"

    verify = _run(["sudo", "pfctl", "-a", PF_ANCHOR_NAME, "-t", TABLE_NAME, "-T", "show"])
    if verify.returncode != 0:
        return (
            "Setup rodou, mas a tabela de bloqueio não carregou no anchor "
            f"({verify.stderr.strip()}). Verifique se '{PF_ANCHOR_NAME}' está em {PF_CONF} "
            "antes de qualquer anchor genérico de terceiros (ex: com.apple)."
        )

    return "Firewall (pf) configurado e ativo. Anchor e tabela de bloqueio confirmados no kernel."


def block(ip: str) -> subprocess.CompletedProcess:
    return _run(["sudo", "pfctl", "-a", PF_ANCHOR_NAME, "-t", TABLE_NAME, "-T", "add", ip])


def unblock(ip: str) -> subprocess.CompletedProcess:
    return _run(["sudo", "pfctl", "-a", PF_ANCHOR_NAME, "-t", TABLE_NAME, "-T", "delete", ip])


def list_raw() -> subprocess.CompletedProcess:
    return _run(["sudo", "pfctl", "-a", PF_ANCHOR_NAME, "-t", TABLE_NAME, "-T", "show"])


def parse_ips(stdout: str) -> list[str]:
    """Cada linha do `pfctl -T show` é só o IP, com espaços ao redor."""
    return [line.strip() for line in stdout.splitlines() if line.strip()]
