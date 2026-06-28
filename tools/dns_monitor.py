"""Monitoramento dos DNS servers da Xfiber (resolvers .90, .91, .92).

Três verificações por servidor, todas usando só stdlib + binários do sistema
(dig/ssl), sem dependência nova:

1. HEALTH CHECK — resolve um domínio de prova via `dig @servidor` e mede a
   latência. Detecta resolver caído (timeout), SERVFAIL/REFUSED (resolver
   respondendo mas quebrado) e latência anormal.
2. AUDITORIA DE PORTAS — verifica quais portas estão abertas. Em um resolver
   dedicado, só 53 (e opcionalmente 853/DoT, 443/DoH) deveriam responder.
   Telnet, RDP, MySQL, FTP abertos são red flags de comprometimento.
3. VALIDADE DE CERTIFICADO — se DoT (853) ou DoH (443) estiverem abertos,
   lê o certificado TLS e avisa quando faltam poucos dias para expirar
   (ou já expirou) — um cert vencido derruba DoT/DoH silenciosamente.

Tie-in de segurança: register_dns_server marca o IP como infraestrutura
CRÍTICA (is_critical=True), então a Nexus nunca auto-bloqueia o próprio
resolver — ver tools/infrastructure.is_critical_ip e _is_safe_to_isolate.

Estratégia de teste: _run_dig, _check_port e _check_cert são isoláveis por
monkeypatch (object-form), igual a _run_nmap em tools/asset_inventory.py.
"""

import json
import re
import shutil
import socket
import ssl
import subprocess

from config import DNS_CERT_WARN_DAYS, DNS_PROBE_DOMAIN
from database.db import (
    add_dns_server,
    list_dns_health_checks as _db_list_dns_health_checks,
    list_dns_servers as _db_list_dns_servers,
    record_dns_health_check,
    remove_dns_server as _db_remove_dns_server,
)
from tools import infrastructure

# Portas de serviço DNS legítimas em um resolver: 53 (Do53), 853 (DoT), 443 (DoH).
DNS_SERVICE_PORTS = [53, 853, 443]
# Portas que NÃO deveriam responder em um resolver dedicado — abertas, são
# indício de comprometimento ou de um host fazendo mais do que deveria.
RISKY_PORTS = [23, 21, 25, 3306, 3389, 445]
# 22 (SSH) é probeado e reportado, mas não tratado como problema: admins
# legitimamente administram o resolver por SSH.
ADMIN_PORTS = [22]
# Portas TLS onde faz sentido checar certificado.
TLS_PORTS = [853, 443]

LATENCY_WARN_MS = 500

_DIG_STATUS_RE = re.compile(r"status:\s*([A-Z]+)")
_DIG_LATENCY_RE = re.compile(r"Query time:\s*(\d+)\s*msec")


def _run_dig(server_ip: str, qname: str, qtype: str = "A", timeout: int = 5) -> str:
    """Roda `dig @server qname qtype` e devolve a saída crua. '' se dig ausente."""
    if not shutil.which("dig"):
        return ""
    try:
        result = subprocess.run(
            ["dig", f"@{server_ip}", qname, qtype, "+time=2", "+tries=1"],
            capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return ""


def _parse_dig(output: str) -> dict:
    """Extrai status, latência e alcançabilidade da saída do dig."""
    status_m = _DIG_STATUS_RE.search(output)
    latency_m = _DIG_LATENCY_RE.search(output)
    status = status_m.group(1) if status_m else ""
    return {
        # Qualquer HEADER com status significa que o servidor respondeu.
        "reachable": bool(status),
        "status": status,
        "latency_ms": int(latency_m.group(1)) if latency_m else -1,
    }


def _check_port(host: str, port: int, timeout: float = 2.0) -> bool:
    """True se a porta TCP aceita conexão (aberta)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def _check_cert(host: str, port: int = 853, timeout: float = 3.0) -> dict:
    """Lê o certificado TLS e calcula dias até expirar.

    Usa contexto sem verificação para conseguir LER o cert mesmo quando é
    interno/self-signed (o objetivo é a data de validade, não confiar na cadeia).
    Retorna {ok, days_left, not_after, error}."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
        if not cert or "notAfter" not in cert:
            # Sem verificação o dict costuma vir vazio; cai no binário.
            return {"ok": False, "error": "cert sem notAfter legível"}
        expire_ts = ssl.cert_time_to_seconds(cert["notAfter"])
        import time
        days_left = int((expire_ts - time.time()) // 86400)
        return {"ok": True, "days_left": days_left, "not_after": cert["notAfter"]}
    except Exception as exc:  # socket, ssl, parse — tudo vira erro reportável
        return {"ok": False, "error": str(exc)[:120]}


def register_dns_server(ip: str, hostname: str = "", description: str = "") -> str:
    """Cadastra um DNS server para monitoramento contínuo.

    Marca o IP como infraestrutura CRÍTICA automaticamente — a Nexus nunca
    auto-bloqueia o próprio resolver."""
    try:
        socket.inet_aton(ip)
    except OSError:
        return f"IP inválido: {ip!r}"
    add_dns_server(ip, hostname, description)
    # Protege o resolver de auto-bloqueio registrando-o como bloco crítico /32.
    infrastructure.register_ip_block(
        f"{ip}/32", description or f"DNS server {hostname or ip}", is_critical=True
    )
    return (
        f"DNS server {ip}{' (' + hostname + ')' if hostname else ''} cadastrado "
        "para monitoramento e marcado como CRÍTICO (protegido de auto-bloqueio)."
    )


def unregister_dns_server(ip: str) -> str:
    """Remove um DNS server do monitoramento.

    NÃO remove a proteção crítica do IP (use unregister_own_ip_block para isso,
    deliberadamente — desproteger um resolver deve ser uma decisão explícita)."""
    _db_remove_dns_server(ip)
    return f"DNS server {ip} removido do monitoramento."


def list_dns_servers() -> str:
    """Lista os DNS servers cadastrados para monitoramento."""
    rows = _db_list_dns_servers()
    if not rows:
        return (
            "Nenhum DNS server cadastrado. Use register_dns_server para "
            "monitorar os resolvers da Xfiber (ex.: .90, .91, .92)."
        )
    lines = [f"DNS servers monitorados ({len(rows)}):"]
    for ip, hostname, description, added_at in rows:
        host_str = f" ({hostname})" if hostname else ""
        lines.append(
            f"  {ip}{host_str} — {description or 'sem descrição'} "
            f"(desde {added_at[:10]})"
        )
    return "\n".join(lines)


def _audit_ports(ip: str) -> tuple[list[int], list[int]]:
    """Retorna (portas_abertas, portas_de_risco_abertas)."""
    open_ports = []
    risky_open = []
    for port in DNS_SERVICE_PORTS + ADMIN_PORTS + RISKY_PORTS:
        if _check_port(ip, port):
            open_ports.append(port)
            if port in RISKY_PORTS:
                risky_open.append(port)
    return sorted(open_ports), sorted(risky_open)


def check_dns_health(server_ip: str, probe_domain: str | None = None) -> str:
    """Roda as 3 verificações em um DNS server, grava o resultado e devolve relatório."""
    probe_domain = probe_domain or DNS_PROBE_DOMAIN
    problems: list[str] = []

    # 1. Health check via dig.
    dig = _parse_dig(_run_dig(server_ip, probe_domain))
    reachable = dig["reachable"]
    latency_ms = dig["latency_ms"]
    status = dig["status"]
    if not reachable:
        problems.append("resolver não respondeu (timeout) — pode estar caído")
    elif status != "NOERROR":
        problems.append(f"resolveu '{probe_domain}' com status {status} (esperado NOERROR)")
    elif latency_ms >= 0 and latency_ms > LATENCY_WARN_MS:
        problems.append(f"latência alta: {latency_ms}ms (limite {LATENCY_WARN_MS}ms)")

    # 2. Auditoria de portas.
    open_ports, risky_open = _audit_ports(server_ip)
    if risky_open:
        problems.append(
            "porta(s) de risco aberta(s) em um resolver: "
            + ", ".join(str(p) for p in risky_open)
        )

    # 3. Validade de certificado (só se houver porta TLS aberta).
    cert_days_left = None
    cert_note = ""
    for tls_port in TLS_PORTS:
        if tls_port in open_ports:
            cert = _check_cert(server_ip, tls_port)
            if cert["ok"]:
                cert_days_left = cert["days_left"]
                if cert_days_left < 0:
                    problems.append(
                        f"certificado em :{tls_port} EXPIRADO há {-cert_days_left} dia(s)"
                    )
                elif cert_days_left < DNS_CERT_WARN_DAYS:
                    problems.append(
                        f"certificado em :{tls_port} expira em {cert_days_left} dia(s)"
                    )
                cert_note = f" | cert :{tls_port} vence em {cert_days_left}d"
            else:
                cert_note = f" | cert :{tls_port} ilegível ({cert['error']})"
            break  # checa o primeiro TLS aberto encontrado

    record_dns_health_check(
        server_ip, reachable, latency_ms, status,
        json.dumps(open_ports), json.dumps(risky_open),
        cert_days_left, json.dumps(problems),
    )

    health = "OK" if not problems else "PROBLEMA"
    lat_str = f"{latency_ms}ms" if latency_ms >= 0 else "n/d"
    lines = [
        f"DNS {server_ip} [{health}] — "
        f"resposta: {status or 'sem resposta'} ({lat_str}) | "
        f"portas: {', '.join(str(p) for p in open_ports) or 'nenhuma'}{cert_note}"
    ]
    for p in problems:
        lines.append(f"  ⚠ {p}")
    return "\n".join(lines)


def check_all_dns_health(probe_domain: str | None = None) -> str:
    """Verifica todos os DNS servers cadastrados. Relatório agregado."""
    rows = _db_list_dns_servers()
    if not rows:
        return (
            "Nenhum DNS server cadastrado para verificar. Use register_dns_server."
        )
    reports = [check_dns_health(ip, probe_domain) for ip, *_ in rows]
    return "\n".join(reports)


def has_problems(report: str) -> bool:
    """True se um relatório de check contém ao menos um problema."""
    return "[PROBLEMA]" in report


def describe_dns_health_history(server_ip: str | None = None, limit: int = 20) -> str:
    """Mostra o histórico recente de verificações de saúde dos DNS servers."""
    rows = _db_list_dns_health_checks(server_ip, limit)
    if not rows:
        return "Nenhuma verificação de DNS registrada ainda."
    lines = [f"Histórico de health check de DNS (últimos {len(rows)}):"]
    for (ip, reachable, latency_ms, query_status, open_ports_json,
         risky_ports_json, cert_days_left, problems_json, checked_at) in rows:
        try:
            problems = json.loads(problems_json)
        except Exception:
            problems = []
        lat_str = f"{latency_ms}ms" if latency_ms >= 0 else "n/d"
        cert_str = f" cert={cert_days_left}d" if cert_days_left is not None else ""
        status_str = "OK" if not problems else f"{len(problems)} problema(s)"
        lines.append(
            f"  [{checked_at[:16]}] {ip} — {query_status or 'sem resposta'} "
            f"({lat_str}){cert_str} → {status_str}"
        )
        for p in problems:
            lines.append(f"      ⚠ {p}")
    return "\n".join(lines)
