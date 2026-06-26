"""Isolamento de rede — abstrai o backend real por plataforma.

macOS usa pfctl (tools/firewall_backends/pf.py); Linux usa iptables+ipset
(tools/firewall_backends/iptables.py). A API pública (setup_firewall,
block_ip, unblock_ip, list_blocked, get_actual_blocked_ips) não muda
entre plataformas — todo o resto do projeto (agente, reconcile.py,
main.py) continua chamando essas funções sem saber qual backend está
ativo.

O backend iptables/ipset foi escrito mas NUNCA testado contra um Linux
real (o ambiente de desenvolvimento é macOS) — só tem cobertura via
mock. Antes de confiar nisso em produção numa máquina Linux, valide
manualmente (ver aviso no módulo do backend).
"""

import ipaddress
import platform

from database.db import log_event, record_blocked_ip, remove_blocked_ip

_SYSTEM = platform.system()

if _SYSTEM == "Darwin":
    from tools.firewall_backends import pf as _backend
elif _SYSTEM == "Linux":
    from tools.firewall_backends import iptables as _backend
else:
    _backend = None


def _require_backend():
    if _backend is None:
        raise RuntimeError(
            f"Nenhum backend de firewall disponível para o sistema '{_SYSTEM}'. "
            "Suportado: Darwin (pfctl) e Linux (iptables/ipset)."
        )
    return _backend


def _validate_ip(ip: str) -> str:
    return str(ipaddress.ip_address(ip))


def setup_firewall() -> str:
    """Configura o backend de firewall da plataforma atual. Idempotente.
    Requer sudo."""
    return _require_backend().setup()


def block_ip(ip: str, reason: str = "") -> str:
    ip = _validate_ip(ip)
    backend = _require_backend()
    log_event("firewall_block_attempt", ip, f"reason={reason!r}", action_taken="executando")
    result = backend.block(ip)
    if result.returncode != 0:
        log_event("firewall_block_failed", ip, result.stderr.strip(), action_taken="falhou")
        return f"Falha ao bloquear {ip}: {result.stderr.strip()}"
    record_blocked_ip(ip, reason)
    log_event("firewall_block_confirmed", ip, f"reason={reason!r}", action_taken="bloqueado")
    return f"IP {ip} isolado/bloqueado com sucesso."


def unblock_ip(ip: str) -> str:
    ip = _validate_ip(ip)
    backend = _require_backend()
    log_event("firewall_unblock_attempt", ip, "", action_taken="executando")
    result = backend.unblock(ip)
    if result.returncode != 0:
        log_event("firewall_unblock_failed", ip, result.stderr.strip(), action_taken="falhou")
        return f"Falha ao desbloquear {ip}: {result.stderr.strip()}"
    remove_blocked_ip(ip)
    log_event("firewall_unblock_confirmed", ip, "", action_taken="desbloqueado")
    return f"IP {ip} desbloqueado."


def list_blocked() -> str:
    backend = _require_backend()
    result = backend.list_raw()
    if result.returncode != 0:
        return f"Falha ao listar bloqueios: {result.stderr.strip()}"
    ips = backend.parse_ips(result.stdout)
    return "\n".join(ips) if ips else "Nenhum IP bloqueado atualmente."


def get_actual_blocked_ips() -> set[str] | None:
    """Lê o estado REAL do backend (não o que o banco acha que está
    bloqueado). Retorna None se não conseguir consultar (ex: backend não
    configurado ainda), para o caller distinguir "vazio" de "erro"."""
    backend = _require_backend()
    result = backend.list_raw()
    if result.returncode != 0:
        return None
    ips = set()
    for candidate in backend.parse_ips(result.stdout):
        try:
            ips.add(_validate_ip(candidate))
        except ValueError:
            continue
    return ips
