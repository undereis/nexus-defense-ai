"""Listas globais de IPs/redes maliciosas conhecidas, atualizadas
periodicamente — bloquear ANTES de o IP atacar, não depois.

Diferente de tools/threat_feeds.py (consulta pontual sob demanda, por
IP, via AbuseIPDB/VirusTotal/Shodan), isto baixa listas completas e
gratuitas, sem chave de API, e guarda localmente para checagem rápida
contra qualquer IP que conectar:

- Spamhaus DROP: blocos de rede usados quase exclusivamente para
  atividade maliciosa (sequestrados, "bulletproof hosting").
- Feodo Tracker (abuse.ch): IPs de C2 de botnets bancárias conhecidas.
- Emerging Threats: lista de IPs comprometidos/atacantes observados
  recentemente em honeypots e sensores da comunidade.

Todas são públicas e gratuitas, sem necessidade de chave/conta.
"""

import ipaddress

import requests

from database.db import (
    count_feed_entries_by_source,
    get_all_feed_entries,
    replace_feed_entries,
)

_TIMEOUT_SECONDS = 30

FEED_URLS = {
    "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
    "feodo_tracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "emerging_threats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
}


def _parse_feed_text(text: str) -> list[str]:
    """Extrai IPs/CIDRs válidos de um feed em texto puro, ignorando
    comentários (linhas começando com ';' ou '#') e linhas vazias."""
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith((";", "#")):
            continue
        candidate = line.split(";")[0].strip()  # Spamhaus tem "; SBLxxxx" depois do CIDR
        candidate = candidate.split()[0] if candidate.split() else ""
        try:
            ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            continue
        entries.append(candidate)
    return entries


def refresh_feed(source: str) -> str:
    """Baixa e substitui as entradas de uma fonte específica."""
    url = FEED_URLS.get(source)
    if not url:
        return f"Fonte desconhecida: {source!r}. Opções: {', '.join(FEED_URLS)}."
    try:
        resp = requests.get(url, timeout=_TIMEOUT_SECONDS, headers={"User-Agent": "Nexus-Defense-AI/1.0"})
        resp.raise_for_status()
    except requests.RequestException as exc:
        return f"Falha ao baixar feed {source}: {exc}"

    entries = _parse_feed_text(resp.text)
    replace_feed_entries(source, entries)
    return f"Feed {source} atualizado: {len(entries)} entrada(s)."


def refresh_all_feeds() -> str:
    """Atualiza todas as fontes configuradas, uma por uma — uma fonte
    falhando não impede as outras de atualizar."""
    results = [refresh_feed(source) for source in FEED_URLS]
    return "\n".join(results)


def describe_feed_status() -> str:
    rows = count_feed_entries_by_source()
    if not rows:
        return "Nenhum feed de threat intel foi atualizado ainda. Rode refresh_all_feeds()."
    lines = ["Status dos feeds de threat intel:"]
    for source, total, fetched_at in rows:
        lines.append(f"  {source}: {total} entrada(s), última atualização {fetched_at}")
    return "\n".join(lines)


def check_ip_against_feeds(ip: str) -> list[str]:
    """Retorna a lista de fontes (Spamhaus/Feodo/ET) em que esse IP
    aparece, vazia se estiver limpo em todas. Compara contra IPs e CIDRs."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []
    matches = []
    for source, value in get_all_feed_entries():
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if addr in network:
            matches.append(source)
    return matches


def describe_ip_feed_check(ip: str) -> str:
    matches = check_ip_against_feeds(ip)
    if not matches:
        return f"{ip}: não encontrado em nenhum feed de threat intel conhecido (Spamhaus/Feodo/ET)."
    return f"{ip}: ENCONTRADO em {len(matches)} feed(s) malicioso(s) conhecido(s): {', '.join(matches)}."
