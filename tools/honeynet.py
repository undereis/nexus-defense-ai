"""Honeynet declarativa: um segmento de rede inteiro que NÃO deveria ter
tráfego legítimo nunca — qualquer pacote ali é, por definição, ataque
(não há threshold, não há "talvez seja falso positivo").

Diferente do honeypot (uma porta isolada que a Nexus escuta) e do
honeytoken (um arquivo/credencial plantado), a honeynet é sobre um
INTERVALO de IPs inteiro da rede real da Xfiber — ex: um /28 reservado,
nunca anunciado, nunca usado por equipamento de cliente.

LIMITAÇÃO REAL, documentada explicitamente: este módulo só declara os
intervalos e cruza contra o que outras fontes JÁ capturam (alertas de
DPI/Suricata) — não há, neste ambiente, uma forma de "ver" todo o
tráfego de um segmento de rede dedicado sem hardware real (Mikrotik
fazendo port mirroring da VLAN para a interface onde o Suricata
escuta). Até esse mirroring existir, isto funciona em modo
"declarado, mas sem visibilidade total" — qualquer alerta de DPI cuja
origem OU destino caia no intervalo declarado já é cruzado
automaticamente, mas tráfego que o DPI não vir (ex: se a interface
monitorada não inclui aquele segmento) não é detectado por aqui.
"""

import ipaddress

from database.db import (
    declare_honeynet_range,
    list_honeynet_ranges,
    log_event,
    remove_honeynet_range,
)
from tools import dpi


def declare_range(cidr: str, description: str) -> str:
    """Declara um intervalo de IPs como honeynet — nenhum tráfego ali
    deveria existir nunca. Ex: '10.50.0.0/28', 'segmento reservado,
    nunca anunciado via DHCP/PPPoE'."""
    try:
        normalized = str(ipaddress.ip_network(cidr, strict=False))
    except ValueError as exc:
        return f"CIDR inválido: {cidr!r} ({exc})"
    declare_honeynet_range(normalized, description)
    log_event("honeynet_declared", None, f"cidr={normalized} description={description!r}", action_taken="declarado")
    return f"Honeynet declarada: {normalized} ({description})."


def undeclare_range(cidr: str) -> str:
    try:
        normalized = str(ipaddress.ip_network(cidr, strict=False))
    except ValueError as exc:
        return f"CIDR inválido: {cidr!r} ({exc})"
    removed = remove_honeynet_range(normalized)
    if not removed:
        return f"Nenhuma honeynet declarada com o CIDR {normalized}."
    log_event("honeynet_undeclared", None, f"cidr={normalized}", action_taken="removido")
    return f"Honeynet {normalized} removida."


def list_ranges() -> str:
    rows = list_honeynet_ranges()
    if not rows:
        return "Nenhuma honeynet declarada ainda."
    lines = ["Honeynets declaradas:"]
    for cidr, description, declared_at in rows:
        lines.append(f"  {cidr} — {description} (desde {declared_at})")
    return "\n".join(lines)


def is_in_honeynet(ip: str) -> str | None:
    """Retorna a descrição da honeynet se o IP cair em algum intervalo
    declarado, ou None se estiver limpo."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for cidr, description, _declared_at in list_honeynet_ranges():
        if addr in ipaddress.ip_network(cidr):
            return description
    return None


def check_dpi_traffic_against_honeynet() -> list[tuple[str, str]]:
    """Cruza TODOS os alertas de DPI já registrados (não só os
    categorizados como ataque — presença sozinha já é o sinal numa
    honeynet) contra os intervalos declarados. Retorna [(ip_violador,
    descrição)] — o IP REPORTADO é sempre quem violou a honeynet, não o
    endereço da honeynet em si:
    - destino dentro da honeynet -> violador é a ORIGEM (alguém alcançou
      um segmento morto de fora).
    - origem dentro da honeynet -> violador é a própria origem (algo
      está gerando tráfego de DENTRO do segmento morto — ainda mais
      grave, sugere host comprometido ou mal configurado ali)."""
    if not list_honeynet_ranges():
        return []

    hits = []
    seen_ips = set()
    for entry in dpi.get_alert_entries():
        src_ip, dest_ip = entry.get("src_ip"), entry.get("dest_ip")

        if src_ip and src_ip not in seen_ips:
            description = is_in_honeynet(src_ip)
            if description:
                hits.append((src_ip, f"{description} (origem dentro do segmento)"))
                seen_ips.add(src_ip)
                continue  # origem já dentro da honeynet é o caso mais grave, não precisa checar destino

        if dest_ip and src_ip and src_ip not in seen_ips:
            description = is_in_honeynet(dest_ip)
            if description:
                hits.append((src_ip, f"{description} (alcançou {dest_ip})"))
                seen_ips.add(src_ip)
    return hits


def describe_honeynet_violations() -> str:
    hits = check_dpi_traffic_against_honeynet()
    if not list_honeynet_ranges():
        return "Nenhuma honeynet declarada ainda — declare um intervalo com declare_range() primeiro."
    if not hits:
        return "Nenhuma violação de honeynet detectada nos alertas de DPI capturados até agora."
    lines = [f"VIOLAÇÃO DE HONEYNET — {len(hits)} IP(s) tocaram segmento que não deveria ter tráfego:"]
    for ip, description in hits:
        lines.append(f"  {ip} -> {description}")
    return "\n".join(lines)
