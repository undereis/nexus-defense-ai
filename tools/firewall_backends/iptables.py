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
RATE_SET_NAME = "nexus_ratelist"
ASN_SET_NAME = "nexus_asnblocklist"
_HASHLIMIT_ABOVE = "30/minute"
_HASHLIMIT_BURST = "20"


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


def setup_ratelimit() -> str:
    """Cria ipset nexus_ratelist (hash:ip) e regra hashlimit em INPUT.
    Idempotente. IPs no set são throttled a {_HASHLIMIT_ABOVE} com burst
    de {_HASHLIMIT_BURST} — pacotes acima da taxa são dropados."""
    create = _run(["sudo", "ipset", "create", RATE_SET_NAME, "hash:ip", "-exist"])
    if create.returncode != 0:
        return f"Falha ao criar ipset de rate limit: {create.stderr.strip()}"
    check = _run([
        "sudo", "iptables", "-C", "INPUT",
        "-m", "set", "--match-set", RATE_SET_NAME, "src",
        "-m", "hashlimit", "--hashlimit-name", "nexus_rl",
        "--hashlimit-mode", "srcip",
        "--hashlimit-above", _HASHLIMIT_ABOVE,
        "--hashlimit-burst", _HASHLIMIT_BURST,
        "-j", "DROP",
    ])
    if check.returncode != 0:
        insert = _run([
            "sudo", "iptables", "-A", "INPUT",
            "-m", "set", "--match-set", RATE_SET_NAME, "src",
            "-m", "hashlimit", "--hashlimit-name", "nexus_rl",
            "--hashlimit-mode", "srcip",
            "--hashlimit-above", _HASHLIMIT_ABOVE,
            "--hashlimit-burst", _HASHLIMIT_BURST,
            "-j", "DROP",
        ])
        if insert.returncode != 0:
            return f"Falha ao inserir regra de rate limit: {insert.stderr.strip()}"
    return "Rate limit (hashlimit) configurado."


def rate_limit(ip: str) -> subprocess.CompletedProcess:
    return _run(["sudo", "ipset", "add", RATE_SET_NAME, ip, "-exist"])


def unrate_limit(ip: str) -> subprocess.CompletedProcess:
    return _run(["sudo", "ipset", "del", RATE_SET_NAME, ip])


def list_rate_limited_raw() -> subprocess.CompletedProcess:
    return _run(["sudo", "ipset", "list", RATE_SET_NAME, "-output", "save"])


def setup_asn_block() -> str:
    """Cria ipset nexus_asnblocklist (hash:net — aceita CIDRs) e regra em INPUT.
    Idempotente."""
    create = _run(["sudo", "ipset", "create", ASN_SET_NAME, "hash:net", "-exist"])
    if create.returncode != 0:
        return f"Falha ao criar ipset ASN: {create.stderr.strip()}"
    check = _run([
        "sudo", "iptables", "-C", "INPUT",
        "-m", "set", "--match-set", ASN_SET_NAME, "src", "-j", "DROP",
    ])
    if check.returncode != 0:
        insert = _run([
            "sudo", "iptables", "-I", "INPUT", "2",
            "-m", "set", "--match-set", ASN_SET_NAME, "src", "-j", "DROP",
        ])
        if insert.returncode != 0:
            return f"Falha ao inserir regra ASN: {insert.stderr.strip()}"
    return "ASN block set (hash:net) configurado."


def block_cidr(cidr: str) -> subprocess.CompletedProcess:
    """Adiciona CIDR ao ipset hash:net — suporta blocos como 203.0.113.0/24."""
    return _run(["sudo", "ipset", "add", ASN_SET_NAME, cidr, "-exist"])


def unblock_cidr(cidr: str) -> subprocess.CompletedProcess:
    return _run(["sudo", "ipset", "del", ASN_SET_NAME, cidr])
