"""Inventário automático de ativos da rede própria.

Varre periodicamente os blocos IP registrados em tools/infrastructure.py,
detecta dispositivos novos e mudanças de configuração (portas abertas,
hostname, OS) comparando com o estado anterior.

Estratégia de scan deliberadamente conservadora:
- -sn (ping scan): só descobre hosts ativos, sem varredura de portas.
- -T2 (Polite): throttle automático para não inundar a rede nem disparar
  o próprio monitor de DDoS.
- mode='light' adiciona top 100 portas TCP, suficiente para detectar
  serviços comuns (SSH, HTTP, MySQL, RDP, Mikrotik API 8728/8729).

O diff automático registra em asset_changes qualquer mudança de hostname,
portas ou OS desde o último scan — base para detectar um roteador
comprometido que abriu uma nova porta, ou um novo device não autorizado.
"""

import json
import re
import shutil
import subprocess

from database.db import (
    list_asset_changes as _db_list_asset_changes,
    list_assets,
    log_event,
    record_asset_change,
    upsert_asset,
)
from tools.infrastructure import list_ip_blocks

_NMAP_HOST_RE = re.compile(
    r"Nmap scan report for (?:(\S+) \()?(\d+\.\d+\.\d+\.\d+)\)?"
)
_NMAP_PORT_RE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)", re.MULTILINE)
_NMAP_OS_RE = re.compile(r"OS details: (.+)$", re.MULTILINE)


def _run_nmap(args: list[str], timeout: int = 180) -> str:
    if not shutil.which("nmap"):
        return ""
    try:
        result = subprocess.run(
            ["nmap"] + args, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return ""


def _parse_hosts(nmap_output: str) -> list[dict]:
    hosts = []
    blocks = re.split(r"(?=Nmap scan report for )", nmap_output)
    for block in blocks:
        m_ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", block)
        if not m_ip or "Host is up" not in block:
            continue
        ip = m_ip.group(1)
        hostname = ""
        m_host = re.search(r"Nmap scan report for (\S+) \(", block)
        if m_host:
            hostname = m_host.group(1)
        ports = [
            f"{m.group(1)}/{m.group(2)}" for m in _NMAP_PORT_RE.finditer(block)
        ]
        os_guess = ""
        m_os = _NMAP_OS_RE.search(block)
        if m_os:
            os_guess = m_os.group(1)[:200]
        hosts.append({"ip": ip, "hostname": hostname, "ports": ports, "os_guess": os_guess})
    return hosts


def scan_network(cidr: str | None = None, mode: str = "passive") -> str:
    """Escaneia um bloco CIDR (ou todos os blocos registrados se cidr=None).

    mode='passive'  — ping scan (-sn): descobre hosts ativos, sem portas.
    mode='light'    — ping + top 100 portas TCP (-T2): detecta serviços.

    Usa -T2 (Polite) para não disparar o monitor de DDoS na própria rede.
    Execute APENAS em blocos próprios registrados em register_own_ip_block."""
    if not shutil.which("nmap"):
        return "nmap não instalado. Rode: brew install nmap"

    blocks = list_ip_blocks()
    if cidr:
        targets = [cidr]
    else:
        targets = [b[0] for b in blocks]

    if not targets:
        return (
            "Nenhum bloco IP registrado. "
            "Use register_own_ip_block para cadastrar sua infraestrutura primeiro."
        )

    all_found: list[dict] = []
    for target in targets:
        if mode == "light":
            args = ["-T2", "-sn", "--top-ports", "100", "-O", "--osscan-guess", target]
        else:
            args = ["-T2", "-sn", target]
        output = _run_nmap(args)
        if output:
            all_found.extend(_parse_hosts(output))

    if not all_found:
        return f"Scan concluído — nenhum host ativo em {', '.join(targets)}."

    new_assets: list[str] = []
    changed_assets: list[str] = []

    for h in all_found:
        ports_json = json.dumps(sorted(h["ports"]))
        is_new, changes = upsert_asset(h["ip"], h["hostname"], ports_json, h["os_guess"])
        if is_new:
            new_assets.append(h["ip"])
            log_event(
                "asset_discovered", h["ip"],
                f"ports={h['ports']} hostname={h['hostname']!r} os={h['os_guess']!r}",
            )
        elif changes:
            changed_assets.append(h["ip"])
            for change_type, old, new in changes:
                record_asset_change(h["ip"], change_type, old, new)
                log_event(
                    "asset_changed", h["ip"],
                    f"{change_type}: {old!r} → {new!r}",
                    action_taken="registrado",
                )

    lines = [f"Scan concluído — {len(all_found)} host(s) ativo(s) em {', '.join(targets)}."]
    if new_assets:
        lines.append(f"  NOVOS ({len(new_assets)}): {', '.join(new_assets)}")
    if changed_assets:
        lines.append(f"  MUDANÇAS ({len(changed_assets)}): {', '.join(changed_assets)}")
    if not new_assets and not changed_assets:
        lines.append("  Sem mudanças desde o último scan.")
    return "\n".join(lines)


def list_known_assets() -> str:
    """Lista todos os ativos descobertos pelo inventário automático."""
    rows = list_assets()
    if not rows:
        return (
            "Inventário vazio — nenhum ativo descoberto ainda. "
            "Use scan_own_network para iniciar."
        )
    lines = [f"Ativos conhecidos ({len(rows)}):"]
    for ip, hostname, ports_json, os_guess, first_seen, last_seen, status in rows:
        try:
            ports = json.loads(ports_json)
        except Exception:
            ports = []
        port_str = (
            ", ".join(ports[:6]) + ("…" if len(ports) > 6 else "")
            if ports else "—"
        )
        host_str = f" ({hostname})" if hostname else ""
        os_str = f" | OS: {os_guess[:50]}" if os_guess else ""
        lines.append(
            f"  {ip}{host_str} | portas: {port_str}{os_str}"
            f" | visto: {last_seen[:16]}"
        )
    return "\n".join(lines)


def list_asset_changes(limit: int = 20) -> str:
    """Lista as últimas mudanças detectadas no inventário de ativos."""
    rows = _db_list_asset_changes(limit)
    if not rows:
        return "Nenhuma mudança de ativo registrada ainda."
    lines = [f"Últimas {len(rows)} mudança(s) de inventário:"]
    for ip, change_type, old_value, new_value, detected_at in rows:
        lines.append(
            f"  [{detected_at[:16]}] {ip} — {change_type}: "
            f"'{old_value[:50]}' → '{new_value[:50]}'"
        )
    return "\n".join(lines)
