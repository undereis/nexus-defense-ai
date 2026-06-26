"""Backend de isolamento via iptables + ipset (Linux).

Usa um ipset dedicado (`nexus_blocklist`) e uma única regra em INPUT que
referencia esse set — mesma filosofia do backend pf: nunca tocar em
regras de firewall que já existem na máquina, só adicionar/remover IPs
do nosso próprio set. Requer privilégios de root (sudo).

NUNCA VALIDADO CONTRA UM LINUX REAL — só testado com subprocess mockado
(tests/test_firewall_iptables.py), porque o ambiente de desenvolvimento
é macOS. Antes de confiar nisso em produção, rode setup()/block()/
unblock()/list_raw() manualmente numa VM/máquina Linux real e confirme
o estado com `iptables -L INPUT -n` e `ipset list nexus_blocklist`.
"""

import subprocess

SET_NAME = "nexus_blocklist"


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def setup() -> str:
    """Cria o ipset e a regra em INPUT, se ainda não existirem. Idempotente."""
    create = _run(["sudo", "ipset", "create", SET_NAME, "hash:ip", "-exist"])
    if create.returncode != 0:
        return f"Falha ao criar ipset: {create.stderr.strip()}"

    check_rule = _run(["sudo", "iptables", "-C", "INPUT", "-m", "set", "--match-set", SET_NAME, "src", "-j", "DROP"])
    if check_rule.returncode != 0:
        insert_rule = _run(
            ["sudo", "iptables", "-I", "INPUT", "-m", "set", "--match-set", SET_NAME, "src", "-j", "DROP"]
        )
        if insert_rule.returncode != 0:
            return f"Falha ao inserir regra iptables: {insert_rule.stderr.strip()}"

    verify = _run(["sudo", "ipset", "list", SET_NAME])
    if verify.returncode != 0:
        return f"Setup rodou, mas não foi possível confirmar o ipset ({verify.stderr.strip()})."

    return "Firewall (iptables/ipset) configurado e ativo. Set e regra em INPUT confirmados."


def block(ip: str) -> subprocess.CompletedProcess:
    return _run(["sudo", "ipset", "add", SET_NAME, ip, "-exist"])


def unblock(ip: str) -> subprocess.CompletedProcess:
    return _run(["sudo", "ipset", "del", SET_NAME, ip])


def list_raw() -> subprocess.CompletedProcess:
    return _run(["sudo", "ipset", "list", SET_NAME, "-output", "save"])


def parse_ips(stdout: str) -> list[str]:
    """`ipset list <set> -output save` imprime uma linha `create ...` e uma
    linha `add <set> <ip>` por membro."""
    ips = []
    prefix = f"add {SET_NAME} "
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith(prefix):
            ips.append(line[len(prefix):].split()[0])
    return ips
