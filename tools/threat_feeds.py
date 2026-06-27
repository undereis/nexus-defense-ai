"""Correlação com feeds externos de threat intelligence.

Diferente de tools/threat_intel.py (memória própria, só do que a Nexus
já viu na sua rede), isto consulta reputação/contexto de fontes externas
com visibilidade global: AbuseIPDB (reports de abuso por outras redes),
VirusTotal (reputação de IP/hash agregando dezenas de engines), Shodan
(serviços expostos publicamente naquele IP).

Todas têm tier gratuito. Sem chave configurada, a consulta correspondente
retorna aviso de "não configurado" em vez de quebrar — mesmo padrão de
tools/notify.py e tools/mikrotik.py.
"""

import requests

from config import ABUSEIPDB_API_KEY, SHODAN_API_KEY, VIRUSTOTAL_API_KEY

_TIMEOUT_SECONDS = 10


def check_abuseipdb(ip: str) -> str:
    """Consulta o histórico de denúncias de abuso de um IP no AbuseIPDB
    (confidence score 0-100, quantos reports, categorias mais comuns)."""
    if not ABUSEIPDB_API_KEY:
        return "AbuseIPDB não configurado (defina ABUSEIPDB_API_KEY no .env — tier gratuito em abuseipdb.com)."
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=_TIMEOUT_SECONDS,
        )
        data = resp.json().get("data", {})
    except (requests.RequestException, ValueError) as exc:
        return f"Falha ao consultar AbuseIPDB para {ip}: {exc}"

    if not data:
        return f"AbuseIPDB: sem dados para {ip} (resposta inesperada da API)."

    score = data.get("abuseConfidenceScore", 0)
    total_reports = data.get("totalReports", 0)
    isp = data.get("isp", "desconhecido")
    country = data.get("countryCode", "?")
    risk = "ALTO" if score >= 75 else "moderado" if score >= 25 else "baixo"
    return (
        f"AbuseIPDB para {ip}: confiança de abuso {score}/100 (risco {risk}), "
        f"{total_reports} denúncia(s) em 90 dias, ISP={isp}, país={country}."
    )


def check_virustotal_ip(ip: str) -> str:
    """Consulta reputação de um IP no VirusTotal (quantas engines de
    segurança marcam esse IP como malicioso/suspeito)."""
    if not VIRUSTOTAL_API_KEY:
        return "VirusTotal não configurado (defina VIRUSTOTAL_API_KEY no .env — tier gratuito em virustotal.com)."
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=_TIMEOUT_SECONDS,
        )
        data = resp.json().get("data", {}).get("attributes", {})
    except (requests.RequestException, ValueError) as exc:
        return f"Falha ao consultar VirusTotal para {ip}: {exc}"

    if not data:
        return f"VirusTotal: sem dados para {ip}."

    stats = data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1
    owner = data.get("as_owner", "desconhecido")
    return (
        f"VirusTotal para {ip}: {malicious}/{total} engines marcaram como malicioso, "
        f"{suspicious}/{total} como suspeito. Dono do AS: {owner}."
    )


def check_virustotal_hash(file_hash: str) -> str:
    """Consulta reputação de um hash de arquivo (MD5/SHA1/SHA256) no
    VirusTotal — use o hash que analyze_suspicious_file já calcula."""
    if not VIRUSTOTAL_API_KEY:
        return "VirusTotal não configurado (defina VIRUSTOTAL_API_KEY no .env — tier gratuito em virustotal.com)."
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=_TIMEOUT_SECONDS,
        )
        if resp.status_code == 404:
            return f"Hash {file_hash} não encontrado no VirusTotal (nunca visto antes, não significa que é seguro)."
        data = resp.json().get("data", {}).get("attributes", {})
    except (requests.RequestException, ValueError) as exc:
        return f"Falha ao consultar VirusTotal para o hash {file_hash}: {exc}"

    stats = data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) or 1
    names = data.get("meaningful_name") or ", ".join(data.get("names", [])[:3]) or "desconhecido"
    return f"VirusTotal para hash {file_hash}: {malicious}/{total} engines marcaram como malicioso. Nome conhecido: {names}."


def check_shodan(ip: str) -> str:
    """Consulta o Shodan: quais serviços/portas estão expostos publicamente
    nesse IP, segundo o último scan deles (não é scan em tempo real)."""
    if not SHODAN_API_KEY:
        return "Shodan não configurado (defina SHODAN_API_KEY no .env — tier gratuito em shodan.io)."
    try:
        resp = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_API_KEY},
            timeout=_TIMEOUT_SECONDS,
        )
        if resp.status_code == 404:
            return f"Shodan: {ip} não tem nenhum serviço indexado (sem dados públicos conhecidos)."
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        return f"Falha ao consultar Shodan para {ip}: {exc}"

    ports = data.get("ports", [])
    org = data.get("org", "desconhecido")
    hostnames = data.get("hostnames", [])
    vulns = data.get("vulns", [])
    lines = [f"Shodan para {ip}: org={org}, portas expostas: {ports or 'nenhuma conhecida'}"]
    if hostnames:
        lines.append(f"Hostnames: {', '.join(hostnames)}")
    if vulns:
        lines.append(f"CVEs conhecidas associadas: {', '.join(vulns[:10])}")
    return "\n".join(lines)


def correlate_ip(ip: str) -> str:
    """Roda todas as consultas externas configuradas para um IP de uma
    vez e junta num único relatório — use isto em vez de chamar as
    funções individuais quando quiser uma visão externa completa."""
    sections = [check_abuseipdb(ip), check_virustotal_ip(ip), check_shodan(ip)]
    return "\n\n".join(sections)
