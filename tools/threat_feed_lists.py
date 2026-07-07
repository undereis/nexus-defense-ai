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

CP-SD Fase 6M: `refresh_all_feeds()` (o disparo real — rede + substituição
do cache local `threat_feed_entries`) passa por `cp.request_action`
(action_type "threat_feed.refresh_lists", changes_state=True) — RBAC nega
sem tocar rede; lab/replay vira DRY_RUN_ONLY (nunca chama requests.get,
nunca substitui o cache). Isso protege os dois call-sites que hoje chamam
`refresh_all_feeds()` direto (o loop `threat_feed_refresh_loop` em main.py
e a tool do agente `refresh_threat_feed_lists`) sem precisar editar nenhum
dos dois — o boundary fica dentro desta função, mesmo padrão já validado em
`tools/billing.py` (Fase 6D/6F) e `tools/siem.py` (Fase 6H). `refresh_feed`
(uma fonte só) e `check_ip_against_feeds`/`describe_ip_feed_check` (leitura
pura do cache já baixado) NÃO são gateados nesta fase — não são os
call-sites de bypass identificados na Fase 6L. Esta fase NÃO fecha o
bypass de `monitor_loop`'s `firewall.block_ip` direto (que CONSOME este
cache) — isso fica para uma fase própria.
"""

import ipaddress
from contextlib import nullcontext

import requests

from core import control_plane as cp
from core import rbac
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


def _refresh_all_feeds_impl() -> str:
    """Implementação real: baixa as 3 fontes e substitui o cache local, uma
    por uma — uma fonte falhando não impede as outras de atualizar. Só deve
    ser chamada como executor de `cp.request_action` (caminho ALLOW)."""
    results = [refresh_feed(source) for source in FEED_URLS]
    return "\n".join(results)


def _threat_feed_principal_context():
    """Identidade a usar na chamada ao Control Plane do refresh real.

    NUNCA sobrescreve um Principal real já propagado no contexto (chat/API/
    Slack/Telegram) — só assume SERVICE_THREAT_FEED_PRINCIPAL quando
    NINGUÉM setou Principal (caso do `threat_feed_refresh_loop` automático,
    que não tem identidade própria). Mesma lição da CP-SD Fase 6D
    (tools/billing.py) e Fase 6H (tools/siem.py): sobrescrever
    incondicionalmente seria elevação de privilégio."""
    if cp.get_current_principal() is not None:
        return nullcontext()
    return cp.principal_context(rbac.SERVICE_THREAT_FEED_PRINCIPAL)


def refresh_all_feeds() -> str:
    """Atualiza todas as fontes configuradas, uma por uma — uma fonte
    falhando não impede as outras de atualizar.

    CP-SD Fase 6M: o refresh real (rede + substituição do cache local)
    passa pelo Control Plane — RBAC nega sem tocar rede; lab/replay vira
    DRY_RUN_ONLY (nunca chama requests.get, nunca substitui
    threat_feed_entries)."""
    def _do_refresh(feed_count: int, sources: list[str]) -> str:
        return _refresh_all_feeds_impl()

    with _threat_feed_principal_context():
        req = cp.make_request(
            "threat_feed.refresh_lists", target="threat_feed_lists",
            params={"feed_count": len(FEED_URLS), "sources": sorted(FEED_URLS)},
        )
        res = cp.request_action(req, executor=_do_refresh, tool_name="cp_threat_feed_refresh_lists")

    if res.status is cp.ActionStatus.DENIED:
        return f"Atualização de feeds NEGADA pela governança: {res.output}"

    if res.status is cp.ActionStatus.DRY_RUN:
        return f"[DRY-RUN] Atualização de feeds não realizada ({res.output})"

    if res.status is cp.ActionStatus.FAILED:
        return f"Atualização de feeds falhou: {res.output}"

    return res.output


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
