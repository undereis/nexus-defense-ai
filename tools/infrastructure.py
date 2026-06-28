"""Mapa de infraestrutura própria da Xfiber.

Registra blocos IP, ASNs e nós de topologia (roteadores, servidores, DNS)
da Xfiber. Alimenta diretamente a proteção do firewall: IPs registrados como
críticos nunca são auto-bloqueados, evitando que o sistema se bloqueie.

Fluxo de uso:
  1. register_own_ip_block("200.100.0.0/22", "Bloco principal Xfiber", is_critical=True)
  2. register_own_asn("AS65001", "ASN Xfiber")
  3. register_topology_node("rb750-core", "router", "192.168.0.1", "Mikrotik principal")
  4. O firewall passa a proteger esses IPs de auto-bloqueio.
"""

import ipaddress

from database.db import (
    add_infrastructure_asn,
    add_ip_block as _db_add_ip_block,
    add_topology_node as _db_add_topology_node,
    list_infrastructure_asns,
    list_ip_blocks,
    list_topology_nodes,
    remove_infrastructure_asn,
    remove_ip_block as _db_remove_ip_block,
    remove_topology_node as _db_remove_topology_node,
)


def is_own_ip(ip: str) -> bool:
    """Retorna True se o IP pertence a algum bloco registrado como infraestrutura própria."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr, *_ in list_ip_blocks():
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def is_critical_ip(ip: str) -> bool:
    """Retorna True se o IP está em um bloco marcado como crítico (nunca auto-bloqueado)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr, _, is_critical, *_ in list_ip_blocks():
        try:
            if is_critical and addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def register_ip_block(cidr: str, description: str = "",
                       is_critical: bool = False, asn: str = "") -> str:
    """Registra um bloco CIDR como infraestrutura própria.

    is_critical=True protege todos os IPs desse bloco contra auto-bloqueio."""
    try:
        cidr = str(ipaddress.ip_network(cidr, strict=False))
    except ValueError as exc:
        return f"CIDR inválido: {exc}"
    _db_add_ip_block(cidr, description, is_critical, asn)
    crit = " [CRÍTICO — protegido contra auto-bloqueio]" if is_critical else ""
    return f"Bloco {cidr} registrado na infraestrutura própria{crit}."


def unregister_ip_block(cidr: str) -> str:
    """Remove um bloco CIDR do mapa de infraestrutura."""
    try:
        cidr = str(ipaddress.ip_network(cidr, strict=False))
    except ValueError as exc:
        return f"CIDR inválido: {exc}"
    _db_remove_ip_block(cidr)
    return f"Bloco {cidr} removido da infraestrutura."


def register_own_asn(asn: str, description: str = "") -> str:
    """Registra um ASN como pertencente à Xfiber."""
    asn = asn.strip().upper()
    if not asn.startswith("AS"):
        asn = f"AS{asn}"
    add_infrastructure_asn(asn, description)
    return f"ASN {asn} registrado como próprio."


def unregister_own_asn(asn: str) -> str:
    """Remove um ASN do registro de infraestrutura."""
    asn = asn.strip().upper()
    if not asn.startswith("AS"):
        asn = f"AS{asn}"
    remove_infrastructure_asn(asn)
    return f"ASN {asn} removido."


def register_topology_node(name: str, node_type: str,
                            ip_or_cidr: str, description: str = "") -> str:
    """Registra um nó de topologia (router, server, dns, firewall, switch, etc.)."""
    _db_add_topology_node(name, node_type, ip_or_cidr, description)
    return f"Nó '{name}' ({node_type} | {ip_or_cidr}) registrado na topologia."


def unregister_topology_node(name: str) -> str:
    """Remove um nó de topologia do registro."""
    _db_remove_topology_node(name)
    return f"Nó '{name}' removido da topologia."


def list_own_infrastructure() -> str:
    """Retorna o mapa completo de infraestrutura: blocos IP, ASNs e topologia."""
    blocks = list_ip_blocks()
    asns = list_infrastructure_asns()
    nodes = list_topology_nodes()

    lines = []

    if blocks:
        lines.append(f"Blocos IP próprios ({len(blocks)}):")
        for cidr, desc, is_crit, asn, added_at in blocks:
            crit = " [CRÍTICO]" if is_crit else ""
            asn_note = f" | ASN {asn}" if asn else ""
            lines.append(
                f"  {cidr}{crit}{asn_note}"
                f" — {desc or 'sem descrição'} (desde {added_at[:10]})"
            )
    else:
        lines.append("Nenhum bloco IP registrado ainda.")

    if asns:
        lines.append(f"\nASNs próprios ({len(asns)}):")
        for asn, desc, added_at in asns:
            lines.append(f"  {asn} — {desc or 'sem descrição'} (desde {added_at[:10]})")

    if nodes:
        lines.append(f"\nTopologia ({len(nodes)} nó(s)):")
        for name, node_type, ip_or_cidr, desc, added_at in nodes:
            lines.append(
                f"  [{node_type}] {name} ({ip_or_cidr})"
                f" — {desc or 'sem descrição'}"
            )

    if not blocks and not asns and not nodes:
        return (
            "Infraestrutura vazia. Use register_own_ip_block para começar a mapear "
            "os blocos IP e sistemas críticos da Xfiber."
        )

    return "\n".join(lines)
