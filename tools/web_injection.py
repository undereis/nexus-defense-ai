"""Teste manual de injeção (SQLi/XSS) contra um parâmetro HTTP específico.

Envia payloads de teste conhecidos no parâmetro indicado e procura por
sinais de vulnerabilidade na resposta (erro de SQL exposto, payload
refletido sem escape). Não-destrutivo: usa apenas GET, nunca tenta
extrair dados reais nem modificar nada no alvo."""

import re

import requests

_HOSTNAME_RE = re.compile(r"^https?://", re.IGNORECASE)

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR "1"="1',
    "1' AND '1'='2",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
]

SQL_ERROR_SIGNATURES = [
    "sql syntax",
    "mysql_fetch",
    "ora-01756",
    "unclosed quotation mark",
    "sqlite3.operationalerror",
    "pg_query",
    "you have an error in your sql syntax",
    "warning: mysql",
]


def _normalize_url(url: str) -> str:
    return url if _HOSTNAME_RE.match(url) else f"https://{url}"


def test_injection(url: str, param: str, payload_type: str = "both") -> str:
    """Testa um parâmetro de query string contra payloads de SQLi e/ou XSS.
    payload_type: 'sqli', 'xss' ou 'both' (padrão)."""
    base_url = _normalize_url(url)
    payloads = []
    if payload_type in ("sqli", "both"):
        payloads += [("SQLi", p) for p in SQLI_PAYLOADS]
    if payload_type in ("xss", "both"):
        payloads += [("XSS", p) for p in XSS_PAYLOADS]
    if not payloads:
        return "payload_type deve ser 'sqli', 'xss' ou 'both'."

    findings = []
    for category, payload in payloads:
        try:
            resp = requests.get(base_url, params={param: payload}, timeout=10)
        except requests.RequestException as exc:
            findings.append(f"[{category}] payload {payload!r}: falha de conexão ({exc})")
            continue

        body_lower = resp.text.lower()
        if category == "SQLi" and any(sig in body_lower for sig in SQL_ERROR_SIGNATURES):
            findings.append(
                f"[SQLi] SUSPEITO: payload {payload!r} expôs erro de SQL na resposta (status {resp.status_code})"
            )
        elif category == "XSS" and payload in resp.text:
            findings.append(
                f"[XSS] SUSPEITO: payload {payload!r} refletido sem escape na resposta (status {resp.status_code})"
            )

    if not findings:
        return f"Nenhum sinal de SQLi/XSS encontrado em {base_url} (param={param}) com os payloads testados."
    return f"Achados em {base_url} (param={param}):\n" + "\n".join(findings)
