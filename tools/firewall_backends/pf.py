"""Backend de isolamento via helper privilegiado e restrito (macOS)."""

import subprocess

HELPER = "/usr/local/libexec/nexus-firewall"


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def _helper(action: str, target: str | None = None) -> subprocess.CompletedProcess:
    cmd = ["sudo", HELPER, action]
    if target is not None:
        cmd.append(target)
    return _run(cmd)


def setup() -> str:
    """Verifica se o helper foi instalado pelo administrador."""
    verify = _helper("list")
    if verify.returncode != 0:
        return (
            "Helper do firewall indisponível. Execute uma vez: "
            "sudo deploy/install_firewall_helper.sh. "
            f"Detalhes: {verify.stderr.strip()}"
        )
    return "Firewall (pf) ativo e helper privilegiado verificado."


def block(ip: str) -> subprocess.CompletedProcess:
    return _helper("block", ip)


def unblock(ip: str) -> subprocess.CompletedProcess:
    return _helper("unblock", ip)


def list_raw() -> subprocess.CompletedProcess:
    return _helper("list")


def parse_ips(stdout: str) -> list[str]:
    """Cada linha do `pfctl -T show` é só o IP/CIDR, com espaços ao redor."""
    return [line.strip() for line in stdout.splitlines() if line.strip()]


def rate_limit(ip: str) -> subprocess.CompletedProcess:
    """Adiciona IP à tabela de rate limiting. Se exceder 20 conn/5s, pf
    promove automaticamente para nexus_blocklist (overload)."""
    return _helper("rate-block", ip)


def unrate_limit(ip: str) -> subprocess.CompletedProcess:
    return _helper("rate-unblock", ip)


def list_rate_limited_raw() -> subprocess.CompletedProcess:
    return _helper("rate-list")


def block_cidr(cidr: str) -> subprocess.CompletedProcess:
    """pf tables aceitam CIDR diretamente — usa a mesma tabela de bloqueio."""
    return _helper("block", cidr)


def unblock_cidr(cidr: str) -> subprocess.CompletedProcess:
    return _helper("unblock", cidr)
