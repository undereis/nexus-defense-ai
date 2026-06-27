"""Whois (domínio/IP) e consulta de ASN por número.

Dois caminhos diferentes, porque servem perguntas diferentes:
- whois_query: "quem registrou esse domínio/IP?" — usa o binário `whois`
  real do sistema (sem chave, sem limite de uso conhecido para consultas
  pontuais).
- asn_lookup: "quem é o dono do AS15169? quais prefixos ele anuncia?" —
  usa a API pública e gratuita do RIPEstat (sem chave), que cobre ASNs de
  qualquer RIR (não só RIPE), porque ela agrega dados globais de BGP.
"""

import re
import shutil
import subprocess

import requests

_DOMAIN_OR_IP_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*$"
)
_ASN_RE = re.compile(r"^(?:AS|as)?(\d{1,10})$")
_TIMEOUT_SECONDS = 10
_RIPESTAT_BASE = "https://stat.ripe.net/data"


def _validate_target(target: str) -> str:
    target = target.strip()
    # Aceita IPv4/IPv6 simples também — a regex de hostname não cobre ':'
    # (IPv6), então tenta como IP primeiro antes de cair na validação de
    # hostname/domínio.
    import ipaddress
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass
    if not _DOMAIN_OR_IP_RE.match(target):
        raise ValueError(f"Target inválido para whois: {target!r}")
    return target


def whois_query(target: str) -> str:
    """Consulta whois real (domínio ou IP) via o binário do sistema.
    Retorna os dados de registro: dono, data de criação, nameservers
    (domínio) ou bloco CIDR/organização responsável (IP)."""
    target = _validate_target(target)
    if not shutil.which("whois"):
        return "Comando 'whois' não está instalado no sistema."
    try:
        result = subprocess.run(["whois", target], capture_output=True, text=True, timeout=_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return f"Consulta whois para {target} excedeu {_TIMEOUT_SECONDS}s e foi interrompida."
    output = result.stdout.strip() or result.stderr.strip()
    return output or f"Whois não retornou dados para {target}."


def _validate_asn(asn: str) -> str:
    match = _ASN_RE.match(asn.strip())
    if not match:
        raise ValueError(f"ASN inválido: {asn!r}. Use um número (ex: '15169' ou 'AS15169').")
    return match.group(1)


def asn_lookup(asn: str) -> str:
    """Consulta quem é o dono de um ASN e quais prefixos IP ele anuncia
    hoje, via API pública do RIPEstat (cobre qualquer RIR, não só
    Europa). Aceita '15169' ou 'AS15169'."""
    number = _validate_asn(asn)
    resource = f"AS{number}"

    try:
        overview = requests.get(
            f"{_RIPESTAT_BASE}/as-overview/data.json", params={"resource": resource}, timeout=_TIMEOUT_SECONDS
        ).json()
        prefixes = requests.get(
            f"{_RIPESTAT_BASE}/announced-prefixes/data.json", params={"resource": resource}, timeout=_TIMEOUT_SECONDS
        ).json()
    except (requests.RequestException, ValueError) as exc:
        return f"Falha ao consultar AS{number}: {exc}"

    o_data = overview.get("data", {})
    if not o_data or o_data.get("holder") is None:
        return f"AS{number} não encontrado ou sem dados públicos."

    holder = o_data.get("holder", "desconhecido")
    is_announced = o_data.get("announced", False)

    prefix_list = [p.get("prefix") for p in prefixes.get("data", {}).get("prefixes", [])]
    total_prefixes = len(prefix_list)
    sample = ", ".join(prefix_list[:10])
    more = f" (+{total_prefixes - 10} outros)" if total_prefixes > 10 else ""

    lines = [
        f"AS{number} — {holder}",
        f"Status: {'anunciado ativamente' if is_announced else 'não está anunciado atualmente'}",
        f"Prefixos anunciados ({total_prefixes}): {sample or '(nenhum)'}{more}",
    ]
    return "\n".join(lines)
