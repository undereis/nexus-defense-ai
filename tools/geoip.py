"""Geolocalização e ASN de IPs via API pública gratuita (ip-api.com, sem
necessidade de chave). Enriquece tudo que a Nexus já sabe sobre um IP com
de onde ele realmente vem — país, cidade, provedor/ASN.

Cacheado em memória por processo: não bate a API de novo para o mesmo IP
na mesma sessão (rate limit gratuito é 45 req/min).
"""

import ipaddress

import requests

_API_URL = "http://ip-api.com/json/{ip}"
_TIMEOUT_SECONDS = 5
_cache: dict[str, dict | None] = {}


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)
    except ValueError:
        return False


def lookup(ip: str) -> dict | None:
    """Retorna dict com country, region, city, isp, org, as_ (ASN), lat, lon,
    ou None se for IP privado/inválido/falha de consulta."""
    if ip in _cache:
        return _cache[ip]

    if not _is_public(ip):
        _cache[ip] = None
        return None

    try:
        resp = requests.get(
            _API_URL.format(ip=ip),
            params={"fields": "status,country,regionName,city,isp,org,as,lat,lon"},
            timeout=_TIMEOUT_SECONDS,
        )
        data = resp.json()
    except (requests.RequestException, ValueError):
        _cache[ip] = None
        return None

    if data.get("status") != "success":
        _cache[ip] = None
        return None

    result = {
        "country": data.get("country", "desconhecido"),
        "region": data.get("regionName", ""),
        "city": data.get("city", ""),
        "isp": data.get("isp", "desconhecido"),
        "org": data.get("org", ""),
        "asn": data.get("as", "desconhecido"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
    }
    _cache[ip] = result
    return result


def describe_location(ip: str) -> str:
    info = lookup(ip)
    if info is None:
        return f"{ip}: sem geolocalização (rede privada/local ou consulta falhou)."
    place = ", ".join(p for p in (info["city"], info["region"], info["country"]) if p)
    return f"{ip}: {place} — ISP/ASN: {info['isp']} ({info['asn']})"
