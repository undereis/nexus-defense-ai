"""Integração com o BrbOS — SO de servidor DNS da BrByte que roda nos
resolvers da Xfiber.

Enquanto tools/dns_monitor.py vê o resolver POR FORA (dig/porta/cert, caixa
preta), esta integração dá visão POR DENTRO via a API REST do BrbOS:

- get_dns_stats(): lê o dashboard de DNS (REQ/HIT/MISS, NXDOMAIN, cache…) e
  grava um snapshot — matéria-prima para detectar amplification, water-torture/
  DGA (pico de NXDOMAIN) e abuso por IP (Fatia 2: baseline + anomalia).
- list_rpz() / block_domain() / unblock_domain(): bloqueio de domínio na camada
  DNS via Response Policy Zone (RPZ) — uma AÇÃO DE RESPOSTA nova, que o firewall
  de pacote não alcança (C2/phishing/DGA).
- ratelimit_status(): lê a configuração de rate limit por IP do resolver.

API REST do BrbOS (mesma porta da interface web, padrão 8080):
    POST /login   (username/password form-urlencoded) -> Set-Cookie BRBOSCookie
    GET/POST <endpoint>  com o cookie, respostas JSON ({"success": true}).
Os caminhos exatos das ações de DNS (_EP_*) são best-effort pela wiki (que
documenta a UI, não cada endpoint) e ficam centralizados aqui para serem
calibrados num só lugar contra a caixa real. Os testes mockam _api_get/
_api_post, então não dependem desses caminhos.

SEGURANÇA:
- Toda ESCRITA (block_domain) exige ALLOW_BRBOS_BLOCK=true E passa pelo gate de
  confirmação fora de banda (tools/risk.py), igual ao ASN block. unblock é
  de-escalação e não passa pelo gate (mesmo critério de asn_block.unblock_asn).
- A Nexus NUNCA bloqueia/sinkhola domínio da própria infraestrutura
  (_is_protected_domain + BRBOS_PROTECTED_DOMAINS) — bloquear o próprio domínio
  derruba a rede inteira. Defesa em profundidade além do gate.
- Sem credenciais, todas as funções avisam "não configurado" em vez de quebrar
  — mesmo padrão de tools/threat_feeds.py / tools/mikrotik.py.

Estratégia de teste: _api_get/_api_post/_login são isoláveis por monkeypatch
(object-form), igual _run_dig em dns_monitor / _run_nmap em asset_inventory.
"""

import json
import re

import requests

from config import (
    ALLOW_BRBOS_BLOCK,
    BRBOS_HOST,
    BRBOS_PASSWORD,
    BRBOS_PORT,
    BRBOS_PROTECTED_DOMAINS,
    BRBOS_USE_TLS,
    BRBOS_USER,
)
from database.db import (
    get_brbos_rpz_action,
    list_brbos_rpz_actions,
    log_event,
    record_brbos_dns_stats,
    record_brbos_rpz_action,
    remove_brbos_rpz_action,
)
from tools import risk as risk_gate

_TIMEOUT_SECONDS = 10

# Prefixo das ações da API. A doc genérica usa "controllrctl"; se a caixa BrbOS
# usar outro (ex.: "brbosctl"), troque só aqui. Endpoints best-effort, a calibrar.
_CTL = "controllrctl"
_EP_DNS_DASHBOARD = f"/{_CTL}/dns/dashboard/info"
_EP_RPZ_LIST = f"/{_CTL}/dns/rpz/list"
_EP_RPZ_ADD = f"/{_CTL}/dns/rpz/add"
_EP_RPZ_DEL = f"/{_CTL}/dns/rpz/del"
_EP_RATELIMIT = f"/{_CTL}/dns/ip_ratelimit/info"

# Políticas RPZ suportadas na Fatia 1 (não precisam de alvo extra). cname
# (sinkhole para um IP) fica para a Fatia 2, quando houver IP de sinkhole.
_RPZ_POLICIES = ("nxdomain", "nodata", "drop")

# Aliases tolerantes para as métricas do dashboard (nomes reais a calibrar).
_METRIC_ALIASES = {
    "total_req": ("total_req", "req", "requests", "total_requests", "queries", "total_queries"),
    "hit": ("hit", "hits", "cache_hit", "cachehit"),
    "miss": ("miss", "misses", "cache_miss", "cachemiss"),
    "nxdomain": ("nxdomain", "nx", "nxdomains", "num_nxdomain", "nxdomain_count"),
}

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.[A-Za-z0-9-]{1,63})+$"
)

# Sessão autenticada cacheada entre chamadas (relogin automático em 401/403).
_session = None


# ---------- infraestrutura HTTP (seams testáveis) ----------

def _base_url() -> str:
    scheme = "https" if BRBOS_USE_TLS else "http"
    return f"{scheme}://{BRBOS_HOST}:{BRBOS_PORT}"


def is_configured() -> bool:
    return bool(BRBOS_HOST and BRBOS_USER and BRBOS_PASSWORD)


def _new_session():
    s = requests.Session()
    if BRBOS_USE_TLS:
        # Boxes BrbOS internos costumam ter cert self-signed e são alcançados
        # por IP (o cert não casa com o IP). verify=False permite ler o canal
        # mesmo assim; a segurança aqui depende de ser rede de gerência/VPN
        # confiável. Para exposição à internet, use um cert válido na frente.
        s.verify = False
        try:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
    return s


def _login():
    """Autentica no BrbOS e devolve uma Session com o cookie. None se falhar."""
    if not is_configured():
        return None
    s = _new_session()
    try:
        resp = s.post(
            f"{_base_url()}/login",
            data={"username": BRBOS_USER, "password": BRBOS_PASSWORD},
            headers={"Accept": "application/json"},
            timeout=_TIMEOUT_SECONDS,
        )
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    return s


def _request(method: str, path: str, **kwargs) -> dict:
    """Chamada autenticada genérica. Faz login/relogin automático. Sempre
    devolve um dict — com a chave '_error' em caso de falha."""
    global _session
    if not is_configured():
        return {"_error": "BrbOS não configurado (defina BRBOS_HOST/USER/PASSWORD no .env)."}
    if _session is None:
        _session = _login()
        if _session is None:
            return {"_error": "falha ao autenticar (cheque host/porta/credenciais)."}
    url = f"{_base_url()}{path}"
    try:
        resp = _session.request(method, url, timeout=_TIMEOUT_SECONDS, **kwargs)
        if resp.status_code in (401, 403):
            # Sessão expirou — tenta reautenticar uma vez.
            _session = _login()
            if _session is None:
                return {"_error": "reautenticação falhou."}
            resp = _session.request(method, url, timeout=_TIMEOUT_SECONDS, **kwargs)
        if resp.status_code >= 400:
            return {"_error": f"HTTP {resp.status_code}"}
        try:
            return resp.json()
        except ValueError:
            return {"_error": "resposta não-JSON do BrbOS (endpoint pode estar errado)."}
    except requests.RequestException as exc:
        return {"_error": f"falha de conexão: {exc}"}


def _api_get(path: str, params: dict | None = None) -> dict:
    return _request("GET", path, params=params or {})


def _api_post(path: str, data: dict | None = None) -> dict:
    return _request("POST", path, data=data or {})


def _ok(data: dict) -> bool:
    """True se uma resposta de escrita indicou sucesso."""
    return "_error" not in data and bool(data.get("success", False))


# ---------- helpers de domínio / proteção ----------

def _normalize_domain(domain: str) -> str:
    """Limpa e valida um domínio. '' se inválido."""
    d = (domain or "").strip().lower().rstrip(".")
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/")[0].split("@")[-1]
    return d if _DOMAIN_RE.match(d) else ""


def _protected_suffixes() -> list[str]:
    return [
        s.strip().lower().lstrip(".")
        for s in BRBOS_PROTECTED_DOMAINS.split(",")
        if s.strip()
    ]


def _is_protected_domain(domain: str) -> bool:
    """True se o domínio é (ou está sob) um sufixo protegido da própria rede."""
    for suffix in _protected_suffixes():
        if domain == suffix or domain.endswith("." + suffix):
            return True
    return False


# ---------- estatísticas (leitura) ----------

def _extract_dns_metrics(data: dict) -> dict:
    """Extrai REQ/HIT/MISS/NXDOMAIN da resposta do dashboard de forma tolerante
    a nomes de campo (a calibrar). Aceita dict plano ou com chave 'data'."""
    src = data.get("data") if isinstance(data.get("data"), dict) else data
    lower = {str(k).lower(): v for k, v in src.items()} if isinstance(src, dict) else {}
    out = {}
    for metric, aliases in _METRIC_ALIASES.items():
        value = None
        for alias in aliases:
            if alias in lower:
                try:
                    value = int(lower[alias])
                except (TypeError, ValueError):
                    value = None
                break
        out[metric] = value
    return out


def _format_dns_stats(metrics: dict, raw: dict) -> str:
    parts = []
    for label, key in (("REQ", "total_req"), ("HIT", "hit"), ("MISS", "miss"),
                       ("NXDOMAIN", "nxdomain")):
        if metrics.get(key) is not None:
            parts.append(f"{label}: {metrics[key]}")
    hit, miss = metrics.get("hit"), metrics.get("miss")
    ratio = ""
    if isinstance(hit, int) and isinstance(miss, int) and (hit + miss) > 0:
        ratio = f" (cache hit ~{round(100 * hit / (hit + miss))}%)"
    if not parts:
        keys = ", ".join(list(raw.keys())[:12]) or "nenhuma"
        return (
            f"BrbOS DNS [{BRBOS_HOST}] — estatísticas recebidas, mas os campos "
            f"esperados (REQ/HIT/MISS/NXDOMAIN) não foram mapeados. Chaves "
            f"disponíveis: {keys}. (Ajustar _extract_dns_metrics.)"
        )
    return f"BrbOS DNS [{BRBOS_HOST}] — " + " | ".join(parts) + ratio


def get_dns_stats() -> str:
    """Lê o dashboard de DNS do BrbOS, grava um snapshot e devolve um resumo
    (REQ/HIT/MISS/NXDOMAIN). Base para detectar anomalia de DNS."""
    data = _api_get(_EP_DNS_DASHBOARD)
    if "_error" in data:
        return f"BrbOS [{BRBOS_HOST or 'sem host'}]: {data['_error']}"
    metrics = _extract_dns_metrics(data)
    record_brbos_dns_stats(
        BRBOS_HOST, json.dumps(data)[:4000],
        metrics.get("total_req"), metrics.get("hit"),
        metrics.get("miss"), metrics.get("nxdomain"),
    )
    return _format_dns_stats(metrics, data)


def list_rpz() -> str:
    """Lista as entradas RPZ existentes no resolver BrbOS (o que está bloqueado/
    redirecionado na camada DNS hoje, incluindo o que não foi a Nexus que pôs)."""
    data = _api_get(_EP_RPZ_LIST)
    if "_error" in data:
        return f"BrbOS: {data['_error']}"
    rows = data.get("data") or data.get("rows") or data.get("rpz") or []
    if not rows:
        return "BrbOS RPZ: nenhuma entrada (ou o campo de dados não foi mapeado)."
    lines = [f"Entradas RPZ no BrbOS ({len(rows)}):"]
    for r in rows[:50]:
        if isinstance(r, dict):
            name = r.get("name") or r.get("domain") or r.get("qname") or "?"
            action = r.get("action") or r.get("policy") or "?"
            lines.append(f"  {name} → {action}")
        else:
            lines.append(f"  {r}")
    return "\n".join(lines)


def ratelimit_status() -> str:
    """Lê a configuração de rate limit por IP do resolver BrbOS."""
    data = _api_get(_EP_RATELIMIT)
    if "_error" in data:
        return f"BrbOS: {data['_error']}"
    return f"BrbOS rate limit (IP) [{BRBOS_HOST}]: {json.dumps(data, ensure_ascii=False)[:800]}"


# ---------- bloqueio de domínio via RPZ (escrita, gated) ----------

def _rpz_add_payload(domain: str, policy: str) -> dict:
    """Monta o payload de criação de regra RPZ. Nomes de campo best-effort pela
    wiki (Nome/Ação/Gatilho) — a calibrar contra a caixa real."""
    return {"name": domain, "action": policy, "trigger": "qname"}


def _execute_block_domain(domain: str, policy: str = "nxdomain", reason: str = "") -> str:
    """Aplica de fato o bloqueio RPZ. Registrado no gate via
    risk_gate.register_action('brbos_block_domain', ...) — NUNCA chamado
    diretamente pelo agente; só roda após confirmação fora de banda."""
    data = _api_post(_EP_RPZ_ADD, _rpz_add_payload(domain, policy))
    if "_error" in data:
        return f"Falha ao bloquear {domain} no BrbOS: {data['_error']}"
    if not _ok(data):
        return f"BrbOS recusou o bloqueio de {domain}: {json.dumps(data, ensure_ascii=False)[:300]}"
    record_brbos_rpz_action(domain, "block", policy, reason)
    log_event(
        "brbos_domain_blocked", None,
        f"domain={domain} policy={policy} reason={reason!r}",
        action_taken="bloqueado via RPZ no BrbOS",
    )
    return f"Domínio {domain} bloqueado no DNS (RPZ {policy}) no resolver BrbOS {BRBOS_HOST}."


def block_domain(domain: str, policy: str = "nxdomain", reason: str = "") -> str:
    """Propõe bloquear um domínio na camada DNS via RPZ — coloca no gate de
    confirmação (código fora de banda obrigatório). Use para C2/phishing/DGA.

    ALLOW_BRBOS_BLOCK=true deve estar no .env. Domínios da própria
    infraestrutura são recusados. policy: nxdomain (padrão) | nodata | drop."""
    if not ALLOW_BRBOS_BLOCK:
        return (
            "ALLOW_BRBOS_BLOCK não habilitado no .env — habilite deliberadamente "
            "antes de bloquear domínios no DNS (afeta a resolução de todos os clientes)."
        )
    if not is_configured():
        return "BrbOS não configurado (defina BRBOS_HOST/USER/PASSWORD no .env)."
    norm = _normalize_domain(domain)
    if not norm:
        return f"Domínio inválido: {domain!r}."
    if policy not in _RPZ_POLICIES:
        return f"Política RPZ inválida: {policy!r}. Use uma de: {', '.join(_RPZ_POLICIES)}."
    if _is_protected_domain(norm):
        return (
            f"BLOQUEIO RECUSADO: {norm} é (ou está sob) um domínio protegido da "
            "própria infraestrutura — bloqueá-lo derrubaria a rede. (Ver "
            "BRBOS_PROTECTED_DOMAINS no .env.)"
        )
    if get_brbos_rpz_action(norm):
        return f"{norm} já consta bloqueado pela Nexus via RPZ."
    summary = (
        f"Bloquear o domínio '{norm}' no DNS (RPZ, política {policy}) no resolver "
        f"BrbOS {BRBOS_HOST}. Motivo: {reason or 'n/d'}. IMPACTO: todos os clientes "
        "da Xfiber deixarão de resolver esse domínio."
    )
    return risk_gate.request_confirmation(
        "brbos_block_domain",
        summary,
        kb_query="DNS RPZ response policy zone sinkhole block malicious domain",
        domain=norm,
        policy=policy,
        reason=reason,
    )


def unblock_domain(domain: str) -> str:
    """Remove um bloqueio RPZ aplicado antes pela Nexus (de-escalação — não passa
    pelo gate, igual a desbloquear um IP/ASN)."""
    norm = _normalize_domain(domain)
    if not norm:
        return f"Domínio inválido: {domain!r}."
    if not get_brbos_rpz_action(norm):
        return f"{norm} não está na lista de domínios bloqueados pela Nexus."
    data = _api_post(_EP_RPZ_DEL, {"name": norm})
    if "_error" in data:
        return f"Falha ao desbloquear {norm} no BrbOS: {data['_error']}"
    if not _ok(data):
        return f"BrbOS recusou o desbloqueio de {norm}: {json.dumps(data, ensure_ascii=False)[:300]}"
    remove_brbos_rpz_action(norm)
    log_event(
        "brbos_domain_unblocked", None, f"domain={norm}",
        action_taken="desbloqueado no RPZ do BrbOS",
    )
    return f"Domínio {norm} desbloqueado no DNS (RPZ) do resolver BrbOS {BRBOS_HOST}."


def list_blocked_domains() -> str:
    """Lista os domínios que a Nexus bloqueou via RPZ (auditoria local)."""
    rows = list_brbos_rpz_actions()
    if not rows:
        return "Nenhum domínio bloqueado pela Nexus via RPZ no BrbOS."
    lines = [f"Domínios bloqueados pela Nexus via RPZ ({len(rows)}):"]
    for domain, action, policy, reason, created_at in rows:
        lines.append(
            f"  {domain} — {action}/{policy} ({reason or 'sem motivo'}, em {created_at[:16]})"
        )
    return "\n".join(lines)
