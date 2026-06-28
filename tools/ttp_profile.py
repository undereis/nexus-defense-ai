"""Perfil de grupo por TTPs (Fase 6, item 3): agrupa IPs atacantes que
compartilham comportamento / origem / técnicas em "grupos" e emite um
perfil preditivo por grupo — "esse grupo vem desse ASN, ataca por volta
das 14h UTC, prefere essas portas, usa essas técnicas".

100% sobre dados que a Nexus JÁ coleta (honeypot_hits, events, geoip) —
não coleta nada novo e não dispara nenhuma ação (read-only, sem gate de
risco). O agrupamento é DETERMINÍSTICO e explicável (single-linkage sobre
um grafo de similaridade), NÃO é ML — mesma filosofia honesta de
`tools/fingerprint.py`.

Limitações assumidas:
- Base nos IPs de honeypot (única fonte com porta/serviço/timing). IPs
  vistos só por volume de tráfego (threat_intel) sem hit de honeypot não
  entram no clustering comportamental nesta versão.
- IPs com menos de MIN_HITS conexões não têm fingerprint confiável e ficam
  de fora do agrupamento (são contados à parte no relatório).
- Single-linkage pode "encadear" grupos por uma ponte fraca; o limiar
  combinado mitiga, mas o relatório SEMPRE lista os membros para
  inspeção humana.
- O timestamp do honeypot tem resolução de 1s; a "hora de pico" é por
  hora-do-dia UTC (bom para padrão diário, não para precisão de minuto).
"""

from collections import Counter
from datetime import datetime

from database.db import (
    get_distinct_honeypot_ips_since,
    get_event_types_for_ip,
    get_honeypot_hits_chronological_for_ip,
    get_honeypot_services_for_ip,
)
from tools import fingerprint, geoip, mitre_attack

# IP precisa de pelo menos isto de conexões para ter fingerprint confiável.
MIN_HITS = fingerprint.MIN_HITS_FOR_RELIABLE_FINGERPRINT
DEFAULT_WINDOW_HOURS = 24 * 7
# Score combinado (0-1) acima do qual dois IPs são unidos no mesmo grupo.
GROUPING_THRESHOLD = 0.6

# Pesos do score de similaridade entre dois IPs (somam 1.0).
_W_BEHAVIOR = 0.4  # fingerprint: sequência de portas + timing
_W_TTP = 0.3       # Jaccard das técnicas MITRE
_W_PORTS = 0.2     # Jaccard das portas tocadas
_W_ASN = 0.1       # mesmo ASN (bônus binário)

# event_type ofensivo -> rótulo amigável da ferramenta/técnica inferida.
_TOOL_HINTS = {
    "hydra_attempt": "Hydra (brute force)",
    "sqlmap_attempt": "SQLMap (SQLi)",
    "hashcat_attempt": "Hashcat (cracking)",
    "john_attempt": "John (cracking)",
}


# ---------- helpers puros ----------

def _hour_of(ts: str) -> int | None:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(ts, fmt).hour
        except ValueError:
            continue
    return None


def _jaccard(a: set, b: set) -> float:
    union = a | b
    return len(a & b) / len(union) if union else 0.0


def _ttps_for_ip(ip: str) -> dict[str, str]:
    """{technique_id: technique_name} de tudo que se sabe do IP (eventos
    de auditoria + serviços de honeypot tocados), via tools/mitre_attack."""
    techs: dict[str, str] = {}
    for et in get_event_types_for_ip(ip):
        t = mitre_attack.map_event_to_ttp(et)
        if t["technique_id"] != "—":
            techs[t["technique_id"]] = t["technique_name"]
    for svc in get_honeypot_services_for_ip(ip):
        t = mitre_attack.map_honeypot_service_to_ttp(svc)
        if t["technique_id"] != "—":
            techs[t["technique_id"]] = t["technique_name"]
    return techs


# ---------- perfil por IP ----------

def build_ip_profile(ip: str) -> dict:
    """Vetor de características de um IP, só de dado já coletado."""
    hits = get_honeypot_hits_chronological_for_ip(ip)  # (port, service, timestamp)
    info = geoip.lookup(ip) or {}
    return {
        "ip": ip,
        "fingerprint": fingerprint.compute_fingerprint(ip),
        "ttps": _ttps_for_ip(ip),
        "ports": {h[0] for h in hits},
        "hours": [h for h in (_hour_of(x[2]) for x in hits) if h is not None],
        "event_types": set(get_event_types_for_ip(ip)),
        "asn": info.get("asn", "desconhecido"),
        "country": info.get("country", "?"),
        "total_hits": len(hits),
        "first_seen": hits[0][2] if hits else None,
        "last_seen": hits[-1][2] if hits else None,
    }


def _similarity(a: dict, b: dict) -> float:
    """Score 0-1 combinando comportamento, TTPs, portas e ASN."""
    behavior = fingerprint.compare_fingerprints(a["fingerprint"], b["fingerprint"])
    ttp = _jaccard(set(a["ttps"]), set(b["ttps"]))
    ports = _jaccard(a["ports"], b["ports"])
    asn = 1.0 if a["asn"] == b["asn"] and a["asn"] != "desconhecido" else 0.0
    return round(_W_BEHAVIOR * behavior + _W_TTP * ttp + _W_PORTS * ports + _W_ASN * asn, 3)


# ---------- clustering (single-linkage via union-find) ----------

def _cluster(ips: list[str], profiles: dict[str, dict], threshold: float) -> list[list[str]]:
    parent = {ip: ip for ip in ips}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]  # path compression
            x = parent[x]
        return x

    def union(x: str, y: str) -> None:
        parent[find(x)] = find(y)

    for i in range(len(ips)):
        for j in range(i + 1, len(ips)):
            if _similarity(profiles[ips[i]], profiles[ips[j]]) >= threshold:
                union(ips[i], ips[j])

    groups: dict[str, list[str]] = {}
    for ip in ips:
        groups.setdefault(find(ip), []).append(ip)
    for members in groups.values():
        members.sort()
    # grupos maiores primeiro; desempate determinístico pelo 1º membro
    return sorted(groups.values(), key=lambda g: (-len(g), g[0]))


# ---------- síntese do perfil de grupo ----------

def _summarize_group(label: str, members: list[str], profiles: dict[str, dict]) -> dict:
    asns: Counter = Counter()
    countries: Counter = Counter()
    ports: Counter = Counter()
    hours: Counter = Counter()
    ttps: dict[str, str] = {}
    event_types: set[str] = set()
    total_hits = 0
    firsts, lasts = [], []
    for ip in members:
        p = profiles[ip]
        if p["asn"] != "desconhecido":
            asns[p["asn"]] += 1
        countries[p["country"]] += 1
        ports.update(p["ports"])
        hours.update(p["hours"])
        ttps.update(p["ttps"])
        event_types.update(p["event_types"])
        total_hits += p["total_hits"]
        if p["first_seen"]:
            firsts.append(p["first_seen"])
        if p["last_seen"]:
            lasts.append(p["last_seen"])
    return {
        "label": label,
        "members": members,
        "size": len(members),
        "asns": asns.most_common(),
        "countries": countries.most_common(),
        "top_ports": ports.most_common(5),
        "peak_hours": hours.most_common(3),
        "ttps": ttps,
        "tools": sorted({_TOOL_HINTS[e] for e in event_types if e in _TOOL_HINTS}),
        "total_hits": total_hits,
        "first_seen": min(firsts) if firsts else None,
        "last_seen": max(lasts) if lasts else None,
    }


# ---------- API pública ----------

def profile_groups(hours: float = DEFAULT_WINDOW_HOURS, threshold: float = GROUPING_THRESHOLD) -> list[dict]:
    """Lista de grupos (dicts de perfil), maiores primeiro. Só IPs com
    fingerprint confiável (>= MIN_HITS) entram no agrupamento."""
    profiles = {ip: build_ip_profile(ip) for ip in get_distinct_honeypot_ips_since(hours)}
    eligible = sorted(ip for ip, p in profiles.items() if p["total_hits"] >= MIN_HITS)
    clusters = _cluster(eligible, profiles, threshold)
    return [_summarize_group(f"G{i + 1}", members, profiles) for i, members in enumerate(clusters)]


def _predictive_line(g: dict) -> str:
    parts = []
    if g["asns"]:
        parts.append(f"origem provável {g['asns'][0][0]}")
    if g["peak_hours"]:
        parts.append(f"ataca por volta das {g['peak_hours'][0][0]:02d}h UTC")
    if g["top_ports"]:
        parts.append("mira portas " + "/".join(str(p) for p, _ in g["top_ports"][:3]))
    if g["tools"]:
        parts.append("usando " + ", ".join(g["tools"]))
    return "Previsão: " + "; ".join(parts) + "." if parts else "Sinal insuficiente para previsão."


def _format_group(g: dict) -> list[str]:
    lines = [f"━━ Grupo {g['label']} — {g['size']} IP(s), {g['total_hits']} conexão(ões) ━━"]
    lines.append("  📍 Origem (ASN): " + (", ".join(f"{a} ({n})" for a, n in g["asns"]) or "desconhecida"))
    if g["countries"]:
        lines.append("  🌎 Países: " + ", ".join(f"{c} ({n})" for c, n in g["countries"]))
    if g["peak_hours"]:
        lines.append("  🕐 Pico (hora-do-dia): " + ", ".join(f"{h:02d}h UTC ({n}x)" for h, n in g["peak_hours"]))
    if g["top_ports"]:
        lines.append("  🔌 Portas preferidas: " + ", ".join(f"{p} ({n}x)" for p, n in g["top_ports"]))
    if g["ttps"]:
        lines.append("  🗺️ TTPs: " + ", ".join(f"{tid} ({name})" for tid, name in sorted(g["ttps"].items())))
    if g["tools"]:
        lines.append("  🛠️ Ferramentas observadas: " + ", ".join(g["tools"]))
    lines.append(f"  📅 Visto: {g['first_seen']} → {g['last_seen']}")
    lines.append("  🖥️ Membros: " + ", ".join(g["members"]))
    lines.append("  🔮 " + _predictive_line(g))
    return lines


def profile_attacker_groups(hours: float = DEFAULT_WINDOW_HOURS) -> str:
    """Relatório de inteligência: agrupa os atacantes de honeypot da janela
    em grupos por TTP/comportamento/origem e descreve cada grupo."""
    all_ips = get_distinct_honeypot_ips_since(hours)
    if not all_ips:
        return f"Nenhum IP tocou honeypot nas últimas {hours:g}h — sem dados para perfilar grupos."
    profiles = {ip: build_ip_profile(ip) for ip in all_ips}
    eligible = sorted(ip for ip in all_ips if profiles[ip]["total_hits"] >= MIN_HITS)
    skipped = [ip for ip in all_ips if ip not in eligible]
    clusters = _cluster(eligible, profiles, GROUPING_THRESHOLD)

    out = [
        f"═══ PERFIL DE GRUPOS POR TTP (últimas {hours:g}h) ═══",
        f"{len(all_ips)} IP(s) atacante(s) | {len(clusters)} grupo(s) identificado(s)"
        + (f" | {len(skipped)} IP(s) com poucos hits (< {MIN_HITS}) fora do agrupamento" if skipped else ""),
        "",
    ]
    if not clusters:
        out.append(f"Nenhum IP com conexões suficientes (>= {MIN_HITS}) para agrupar com confiança.")
    for i, members in enumerate(clusters):
        out.extend(_format_group(_summarize_group(f"G{i + 1}", members, profiles)))
        out.append("")
    if skipped:
        out.append("ℹ️ Fora do agrupamento (poucos hits, fingerprint não confiável): " + ", ".join(sorted(skipped)))
    return "\n".join(out).rstrip()


def which_group(ip: str, hours: float = DEFAULT_WINDOW_HOURS) -> str:
    """A que grupo um IP pertence + o perfil desse grupo."""
    groups = profile_groups(hours)
    for g in groups:
        if ip in g["members"]:
            others = [m for m in g["members"] if m != ip]
            lines = [f"{ip} pertence ao grupo {g['label']} ({g['size']} IP(s))."]
            if others:
                lines.append("Outros membros (possível mesmo ator): " + ", ".join(others))
            lines.append("")
            lines.extend(_format_group(g))
            return "\n".join(lines)
    return (
        f"{ip} não está em nenhum grupo na janela de {hours:g}h — "
        f"sem hits de honeypot suficientes (>= {MIN_HITS}) ou nenhum atacante similar."
    )
