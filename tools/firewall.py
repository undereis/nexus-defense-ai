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

from core import operating_mode
from database.db import (
    log_event,
    list_rate_limited_ips,
    record_blocked_ip,
    record_rate_limited,
    remove_blocked_ip,
    remove_rate_limited,
)

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


def _validate_cidr(cidr: str) -> str:
    return str(ipaddress.ip_network(cidr, strict=False))


def _dry_run_if_not_real(action_desc: str, target: str) -> str | None:
    """CINTO DE MODO (Fase 1B) — defesa em profundidade, NÃO substitui o Control
    Plane. Em modo operacional 'lab'/'replay' (ou indeterminado), retorna a
    mensagem de no-op para a primitiva devolver SEM tocar o backend real; em
    'real' retorna None (segue a execução normal). Conservador: na dúvida, no-op.
    Audita o dry-run para deixar rastro. Nunca levanta."""
    mode = operating_mode.current_mode_safe()
    if mode == "real":
        return None
    log_event(
        "firewall_dry_run", target,
        f"action={action_desc} mode={mode}",
        action_taken="no-op (modo não altera estado real)",
    )
    return (
        f"[dry-run] {action_desc} de {target} NÃO executado — modo operacional "
        f"'{mode}' não altera estado real (cinto de modo / defesa em profundidade)."
    )


def setup_firewall() -> str:
    """Configura o backend de firewall da plataforma atual. Idempotente.
    Requer sudo."""
    return _require_backend().setup()


def block_ip(ip: str, reason: str = "") -> str:
    ip = _validate_ip(ip)
    dry = _dry_run_if_not_real("bloqueio", ip)
    if dry is not None:
        return dry
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
    dry = _dry_run_if_not_real("desbloqueio", ip)
    if dry is not None:
        return dry
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


def rate_limit_ip(ip: str, reason: str = "", connections_per_second: int = 10) -> str:
    """Aplica rate limiting a um IP sem bloqueio total — throttle de nível 1,
    antes de decidir por isolamento completo. No pf: max 20 conn/5s com
    auto-promoção para bloqueio se exceder. No Linux: hashlimit 30/min."""
    ip = _validate_ip(ip)
    dry = _dry_run_if_not_real("rate limit", ip)
    if dry is not None:
        return dry
    backend = _require_backend()
    if not hasattr(backend, "rate_limit"):
        return f"Backend {_SYSTEM} não tem suporte a rate limiting ainda."
    result = backend.rate_limit(ip)
    if result.returncode != 0:
        if hasattr(backend, "setup_ratelimit"):
            backend.setup_ratelimit()
            result = backend.rate_limit(ip)
        if result.returncode != 0:
            log_event("firewall_ratelimit_failed", ip, result.stderr.strip(), action_taken="falhou")
            return f"Falha ao aplicar rate limit em {ip}: {result.stderr.strip()}"
    record_rate_limited(ip, connections_per_second, reason)
    log_event("firewall_ratelimit_applied", ip, f"reason={reason!r} cps={connections_per_second}", action_taken="throttled")
    return f"IP {ip} em rate limiting ({connections_per_second} conn/s)."


def unrate_limit_ip(ip: str) -> str:
    """Remove o rate limiting de um IP (não é desbloqueio — só remove o throttle)."""
    ip = _validate_ip(ip)
    dry = _dry_run_if_not_real("remoção de rate limit", ip)
    if dry is not None:
        return dry
    backend = _require_backend()
    if not hasattr(backend, "unrate_limit"):
        return f"Backend {_SYSTEM} não tem suporte a rate limiting."
    result = backend.unrate_limit(ip)
    if result.returncode != 0:
        return f"Falha ao remover rate limit de {ip}: {result.stderr.strip()}"
    remove_rate_limited(ip)
    log_event("firewall_ratelimit_removed", ip, "", action_taken="throttle_removido")
    return f"Rate limit removido de {ip}."


def list_rate_limited() -> str:
    """Lista todos os IPs em rate limiting atualmente."""
    rows = list_rate_limited_ips()
    if not rows:
        return "Nenhum IP em rate limiting no momento."
    lines = ["IPs em rate limiting:"]
    for ip, cps, at, reason in rows:
        lines.append(f"  {ip} — {cps} conn/s desde {at} (motivo: {reason or 'não especificado'})")
    return "\n".join(lines)


def block_cidr(cidr: str, reason: str = "") -> str:
    """Bloqueia um bloco CIDR inteiro (ex: '203.0.113.0/24'). Usado
    principalmente pelo bloqueio de ASN — blast radius alto, usar com
    cuidado."""
    try:
        cidr = _validate_cidr(cidr)
    except ValueError as exc:
        return f"CIDR inválido: {exc}"
    dry = _dry_run_if_not_real("bloqueio de CIDR", cidr)
    if dry is not None:
        return dry
    backend = _require_backend()
    if not hasattr(backend, "block_cidr"):
        return f"Backend {_SYSTEM} não tem suporte a block_cidr."
    if hasattr(backend, "setup_asn_block"):
        backend.setup_asn_block()
    result = backend.block_cidr(cidr)
    if result.returncode != 0:
        log_event("firewall_cidr_block_failed", cidr, result.stderr.strip(), action_taken="falhou")
        return f"Falha ao bloquear CIDR {cidr}: {result.stderr.strip()}"
    log_event("firewall_cidr_blocked", cidr, f"reason={reason!r}", action_taken="bloqueado")
    return f"CIDR {cidr} bloqueado."


def unblock_cidr(cidr: str) -> str:
    """Remove bloqueio de um bloco CIDR."""
    try:
        cidr = _validate_cidr(cidr)
    except ValueError as exc:
        return f"CIDR inválido: {exc}"
    dry = _dry_run_if_not_real("desbloqueio de CIDR", cidr)
    if dry is not None:
        return dry
    backend = _require_backend()
    if not hasattr(backend, "unblock_cidr"):
        return f"Backend {_SYSTEM} não tem suporte a unblock_cidr."
    result = backend.unblock_cidr(cidr)
    if result.returncode != 0:
        return f"Falha ao desbloquear CIDR {cidr}: {result.stderr.strip()}"
    log_event("firewall_cidr_unblocked", cidr, "", action_taken="desbloqueado")
    return f"CIDR {cidr} desbloqueado."


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
