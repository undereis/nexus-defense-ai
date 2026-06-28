"""Análise de ferramentas do atacante (Fase 6, item 2): a partir dos sinais
que a Nexus JÁ captura, infere QUAL ferramenta/família o adversário usou —
scanner, brute-forcer, exploit kit, botnet — em vez de só saber que "um IP
atacou".

Fontes de sinal (todas já persistidas, nenhuma coleta nova):
- User-Agent de disparos de honeytoken (honeytoken_triggers) e, quando o
  Suricata está rodando, dos alertas de DPI (eve.json, best-effort).
- Conjunto de credenciais tentadas no honeypot (honeypot_credentials) —
  dicionários de senha padrão denunciam a família (ex.: defaults do Mirai).
- Comportamento de varredura (honeypot_hits): nº de portas distintas e
  volume → varredura de múltiplas portas (port sweep) vs ataque dirigido.

A classificação é por assinatura/heurística DETERMINÍSTICA e explicável
(substring de User-Agent, match de dicionário conhecido, limiar de
comportamento) — NÃO é ML. Honesto sobre confiança: todo veredito carrega o
SINAL que o sustentou; sem sinal suficiente, devolve "indeterminado".

Read-only: não dispara nenhuma ação, não passa por gate (é análise).

Limitação conhecida: o User-Agent do honeypot HTTP principal ainda NÃO é
persistido (ele é lido e descartado em tools/honeypot.py) — isso é a fatia
2B. Hoje o UA vem de honeytoken_triggers e do DPI.
"""

from database.db import (
    get_attacker_user_agents_for_ip,
    get_honeypot_hits_chronological_for_ip,
    list_honeypot_credentials_for_ip,
)
from tools import dpi

# (substrings em minúsculo, rótulo da ferramenta, categoria). Ordem importa:
# o primeiro match vence, então o mais específico vem antes do genérico.
_UA_SIGNATURES: list[tuple[tuple[str, ...], str, str]] = [
    (("sqlmap",), "sqlmap", "exploração SQLi automatizada"),
    (("nikto",), "Nikto", "scanner web de vulnerabilidade"),
    (("nuclei",), "Nuclei", "scanner de templates de vulnerabilidade"),
    (("wpscan",), "WPScan", "scanner de WordPress"),
    (("gobuster",), "Gobuster", "brute force de diretório/DNS"),
    (("dirbuster", "dirb/"), "DirBuster", "brute force de diretório"),
    (("ffuf",), "ffuf", "fuzzing web"),
    (("hydra",), "Hydra", "brute force de login"),
    (("nmap",), "Nmap (NSE)", "scanner de portas/serviço"),
    (("masscan",), "masscan", "scanner de portas em massa"),
    (("zgrab", "zmap"), "ZMap/zgrab", "scanner de internet em massa"),
    (("metasploit", " msf", "msf/"), "Metasploit", "framework de exploração"),
    (("censys",), "Censys", "scanner de internet (pesquisa)"),
    (("shodan",), "Shodan", "scanner de internet (pesquisa)"),
    (("python-requests", "python-urllib", "python/", "aiohttp"), "script Python", "automação caseira (Python)"),
    (("go-http-client",), "Go-http-client", "automação caseira (Go)"),
    (("libwww-perl", "lwp::"), "libwww-perl", "automação caseira (Perl)"),
    (("curl/",), "curl", "cliente HTTP genérico / script"),
    (("wget",), "wget", "cliente HTTP genérico / script"),
]

# Dicionário default de IoT estilo Mirai (subconjunto representativo,
# público em análises do Mirai). Match forte = botnet IoT.
_MIRAI_DEFAULTS: set[tuple[str, str]] = {
    ("root", "xc3511"), ("root", "vizxv"), ("root", "admin"), ("admin", "admin"),
    ("root", "888888"), ("root", "xmhdipc"), ("root", "default"), ("root", "juantech"),
    ("root", "123456"), ("root", "54321"), ("support", "support"), ("root", ""),
    ("admin", "password"), ("root", "root"), ("root", "12345"), ("user", "user"),
    ("admin", ""), ("root", "pass"), ("admin", "admin1234"), ("guest", "guest"),
    ("guest", "12345"), ("admin", "1111"), ("root", "666666"), ("root", "password"),
    ("root", "1234"), ("root", "klv123"), ("Administrator", "admin"), ("service", "service"),
    ("supervisor", "supervisor"), ("root", "zlxx."), ("root", "7ujMko0vizxv"), ("root", "system"),
}

# defaults triviais comuns (não exclusivos do Mirai) — sinal de brute genérico.
_COMMON_DEFAULTS: set[tuple[str, str]] = {
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"), ("root", "root"),
    ("root", "toor"), ("root", "password"), ("user", "user"), ("test", "test"),
    ("oracle", "oracle"), ("postgres", "postgres"), ("ubnt", "ubnt"), ("pi", "raspberry"),
}

_PORT_SWEEP_MIN_DISTINCT = 4  # nº de portas distintas que caracteriza varredura ampla


# ---------- classificadores puros (sem I/O) ----------

def classify_user_agent(ua: str) -> dict:
    """Classifica um User-Agent numa ferramenta/categoria. Pure: dá pra usar
    com qualquer string que o operador colar."""
    u = (ua or "").lower().strip()
    if not u:
        return {
            "tool": "sem User-Agent",
            "category": "automação crua (sem UA — típico de bot/scanner)",
            "confidence": "média",
            "signal": "User-Agent vazio/ausente",
        }
    for subs, tool, category in _UA_SIGNATURES:
        if any(s in u for s in subs):
            return {"tool": tool, "category": category, "confidence": "alta", "signal": f"User-Agent {ua!r}"}
    if any(b in u for b in ("mozilla", "chrome", "safari", "firefox", "edg/", "opera")):
        return {
            "tool": "navegador (ou UA forjado)",
            "category": "navegador real ou UA falsificado para parecer um",
            "confidence": "baixa",
            "signal": f"User-Agent {ua!r}",
        }
    return {"tool": "desconhecido", "category": "não classificado", "confidence": "baixa", "signal": f"User-Agent {ua!r}"}


def classify_credentials(pairs: list[tuple[str | None, str | None]]) -> dict | None:
    """Infere família a partir do conjunto de credenciais tentadas. None se
    não houver credencial."""
    s = {((u or ""), (p or "")) for u, p in pairs}
    if not s:
        return None
    mirai = s & _MIRAI_DEFAULTS
    if len(mirai) >= 2:
        return {
            "family": "botnet IoT estilo Mirai",
            "confidence": "alta",
            "signal": f"{len(mirai)} credencial(is) do dicionário default do Mirai (ex.: {sorted(mirai)[:3]})",
        }
    common = s & _COMMON_DEFAULTS
    if common:
        return {
            "family": "brute force com defaults comuns",
            "confidence": "média",
            "signal": f"{len(common)} credencial(is) default comum(ns) (ex.: {sorted(common)[:3]})",
        }
    return {
        "family": "brute force / wordlist customizada",
        "confidence": "baixa",
        "signal": f"{len(s)} par(es) de credencial sem match em dicionário conhecido",
    }


def classify_scan_behavior(distinct_ports: int, total_hits: int) -> dict | None:
    """Infere o tipo de varredura pelo nº de portas distintas e volume.
    None se não houver hits. (Timing não entra: honeypot_hits tem resolução
    de 1s, grosseira demais para distinguir velocidade de ferramenta.)"""
    if total_hits <= 0:
        return None
    if distinct_ports >= _PORT_SWEEP_MIN_DISTINCT:
        return {
            "type": "varredura de múltiplas portas (port sweep — masscan/zmap/nmap)",
            "confidence": "média",
            "signal": f"{distinct_ports} portas distintas tocadas",
        }
    if total_hits >= 5 and distinct_ports <= 2:
        return {
            "type": "ataque dirigido a um serviço (brute force / exploit de um alvo)",
            "confidence": "média",
            "signal": f"{total_hits} conexões concentradas em {distinct_ports} porta(s)",
        }
    return {
        "type": "atividade pontual (sondagem leve)",
        "confidence": "baixa",
        "signal": f"{total_hits} conexão(ões) em {distinct_ports} porta(s)",
    }


# ---------- coleta de sinais (I/O) ----------

def _dpi_user_agents_for_ip(ip: str) -> list[str]:
    """Best-effort: extrai User-Agents dos alertas do Suricata para o IP.
    Silencioso se o DPI não estiver rodando ou o eve.json não existir."""
    try:
        entries = dpi.get_alert_entries()
    except Exception:
        return []
    uas = []
    for e in entries:
        if e.get("src_ip") == ip:
            ua = (e.get("http") or {}).get("http_user_agent")
            if ua:
                uas.append(ua)
    return uas


def fingerprint_tools_for_ip(ip: str) -> dict:
    """Junta todos os sinais e classifica a(s) ferramenta(s) do IP."""
    uas = list(dict.fromkeys(get_attacker_user_agents_for_ip(ip) + _dpi_user_agents_for_ip(ip)))
    creds = [(u, p) for (_port, _svc, u, p, _ts) in list_honeypot_credentials_for_ip(ip)]
    hits = get_honeypot_hits_chronological_for_ip(ip)
    distinct_ports = len({h[0] for h in hits})
    return {
        "ip": ip,
        "user_agents": [classify_user_agent(ua) for ua in uas],
        "credentials": classify_credentials(creds),
        "behavior": classify_scan_behavior(distinct_ports, len(hits)),
        "has_signal": bool(uas or creds or hits),
    }


# ---------- formatação / API pública ----------

def describe_user_agent(ua: str) -> str:
    c = classify_user_agent(ua)
    return f"{ua!r} -> {c['tool']} ({c['category']}) — confiança {c['confidence']}"


def fingerprint_attacker_tools(ip: str) -> str:
    """Relatório das ferramentas inferidas para um IP."""
    fp = fingerprint_tools_for_ip(ip)
    if not fp["has_signal"]:
        return f"Sem sinais de ferramenta para {ip} (nenhum User-Agent, credencial ou hit de honeypot registrado)."
    out = [f"═══ FERRAMENTAS DO ATACANTE: {ip} ═══"]

    if fp["user_agents"]:
        out.append("🛠️ User-Agents / ferramentas:")
        for c in fp["user_agents"]:
            out.append(f"  • {c['tool']} ({c['category']}) [confiança {c['confidence']}] — {c['signal']}")
    else:
        out.append("🛠️ User-Agents: nenhum capturado (sem honeytoken/DPI com UA para este IP).")

    if fp["credentials"]:
        c = fp["credentials"]
        out.append(f"🔑 Credenciais: {c['family']} [confiança {c['confidence']}] — {c['signal']}")
    else:
        out.append("🔑 Credenciais: nenhuma tentada no honeypot.")

    if fp["behavior"]:
        c = fp["behavior"]
        out.append(f"📡 Comportamento: {c['type']} [confiança {c['confidence']}] — {c['signal']}")

    return "\n".join(out)
