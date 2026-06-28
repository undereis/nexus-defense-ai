"""Deception ativa (Fase 6, item 4): alimentar o atacante com uma imagem
FALSA e convincente da rede enquanto ele acha que está mapeando a real — ele
gasta tempo e age sobre dados errados, e cada toque num isca é, por
definição, ataque confirmado (não existe tráfego legítimo para um host que
não existe).

Diferença para o que já existe:
- honeypot  = uma porta isolada que a Nexus escuta (passivo: o atacante vem).
- honeytoken = um arquivo/credencial-isca plantado em sistema real.
- honeynet  = um INTERVALO de IPs morto declarado.
- deception ativa (este módulo) = popular esse espaço morto com HOSTS-ISCA
  críveis (hostname plausível, SO, serviços com banners deliberadamente
  "suculentos"/antigos) + gerar o DOCUMENTO de mapa falso que o atacante
  leria. É a camada que CONSTRÓI a mentira, não só espera nela.

LIMITES DE SEGURANÇA (inegociáveis):
- Estritamente DEFENSIVO e dentro do próprio perímetro. Nada aqui ataca a
  infra do adversário (sem hack-back). Só gera conteúdo e registra no DB
  local — não mexe em firewall, BGP, DNS de produção nem em rede.
- Um decoy SÓ pode ocupar IP de espaço morto: precisa cair numa honeynet
  declarada (`tools/honeynet.py`) E nunca pode ser infraestrutura própria/
  crítica (`tools/infrastructure.py`). Isso é o análogo do
  `_is_protected_domain`/`_is_safe_to_isolate`: a Nexus jamais finge ser um
  host real nem coloca isca em cima de equipamento de verdade.

LIMITAÇÃO HONESTA (fatia 4B, ainda não feita): este módulo DECLARA os hosts
falsos e gera os banners prontos para serem servidos, mas SERVIR esses banners
ao vivo na rede (responder a um scan com a versão falsa) exige a camada de
socket do honeypot ligada nesses IPs/portas + port mirroring real no Mikrotik
— a mesma limitação que `tools/honeynet.py` já documenta. Enquanto isso, a
detecção de consumo vem dos sensores que JÁ enxergam o espaço morto (alertas
de DPI cujo destino é um IP-isca), exatamente como a honeynet faz.
"""

import ipaddress
import json
import secrets

from database.db import (
    add_decoy_asset,
    get_decoy_ips,
    list_decoy_assets,
    log_event,
    record_decoy_consumption,
    remove_decoy_asset,
)
from tools import dpi, honeynet, infrastructure

# Perfis de host-isca. Banners deliberadamente ANTIGOS/vulneráveis: o objetivo
# é parecer um alvo fácil e suculento, atraindo o atacante a gastar esforço.
# (port, service, banner_falso)
_PROFILES: dict[str, dict] = {
    "database": {
        "prefix": "srv-db-prod",
        "os": "Ubuntu 16.04 LTS",
        "lure": "alta",
        "services": [
            (22, "ssh", "SSH-2.0-OpenSSH_7.4"),
            (3306, "mysql", "5.5.62-0ubuntu0.14.04.1"),
            (6379, "redis", "Redis 3.0.6"),
        ],
    },
    "backup": {
        "prefix": "bkp-fileserver",
        "os": "CentOS 7",
        "lure": "alta",
        "services": [
            (21, "ftp", "220 (vsFTPd 2.3.4)"),
            (22, "ssh", "SSH-2.0-OpenSSH_6.6.1"),
            (445, "smb", "Samba 3.6.23"),
        ],
    },
    "iot_camera": {
        "prefix": "cam-dvr",
        "os": "Embedded Linux 2.6",
        "lure": "média",
        "services": [
            (23, "telnet", "BusyBox v1.19 login:"),
            (80, "http", "Boa/0.94.14rc21"),
            (554, "rtsp", "RTSP/1.0 200 OK"),
        ],
    },
    "vpn_gateway": {
        "prefix": "vpn-gw",
        "os": "Linux (gateway)",
        "lure": "alta",
        "services": [
            (443, "https", "OpenVPN/2.3.2"),
            (500, "ike", "ISAKMP"),
            (22, "ssh", "SSH-2.0-OpenSSH_6.6.1"),
        ],
    },
    "web_intranet": {
        "prefix": "web-intranet",
        "os": "Debian 9",
        "lure": "média",
        "services": [
            (80, "http", "Apache/2.4.10 (Debian)"),
            (8080, "http-alt", "Apache Tomcat/7.0.52"),
            (22, "ssh", "SSH-2.0-OpenSSH_6.7p1"),
        ],
    },
}


def list_profiles() -> list[str]:
    return list(_PROFILES)


# ---------- segurança: onde um decoy PODE existir ----------

def _is_safe_decoy_ip(ip: str) -> tuple[bool, str]:
    """Um decoy só pode ocupar espaço morto: dentro de uma honeynet declarada
    E nunca infraestrutura própria/crítica. Retorna (ok, motivo)."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False, f"IP inválido: {ip!r}"
    if infrastructure.is_own_ip(ip):
        return False, (
            f"{ip} é infraestrutura própria — a Nexus nunca planta isca em cima "
            "de equipamento real nem finge ser um host de verdade."
        )
    if infrastructure.is_critical_ip(ip):
        return False, f"{ip} é IP crítico — recusado."
    if honeynet.is_in_honeynet(ip) is None:
        return False, (
            f"{ip} não está em nenhuma honeynet declarada. Decoys só vivem em "
            "espaço morto: declare a faixa com honeynet.declare_range() antes "
            "(qualquer tráfego ali já é ataque por definição)."
        )
    return True, "ok"


def _allocate_decoy_ip() -> str | None:
    """Escolhe o primeiro IP-host utilizável de uma honeynet declarada que
    ainda não esteja ocupado por outro decoy. None se não houver honeynet ou
    espaço livre."""
    used = get_decoy_ips()
    for cidr, _desc, _declared_at in honeynet.list_honeynet_ranges():
        try:
            net = ipaddress.ip_network(cidr)
        except ValueError:
            continue
        hosts = net.hosts() if net.num_addresses > 2 else iter([net.network_address])
        for host in hosts:
            candidate = str(host)
            if candidate in used:
                continue
            if infrastructure.is_own_ip(candidate) or infrastructure.is_critical_ip(candidate):
                continue
            return candidate
    return None


# ---------- geração / deploy ----------

def generate_decoy_spec(profile: str, hostname: str | None = None) -> dict | None:
    """Monta a especificação de um host-isca (sem persistir). None se o
    perfil não existe."""
    p = _PROFILES.get(profile)
    if p is None:
        return None
    suffix = secrets.token_hex(2)
    return {
        "decoy_id": secrets.token_hex(6),
        "hostname": hostname or f"{p['prefix']}-{suffix}",
        "os": p["os"],
        "profile": profile,
        "services": [{"port": port, "service": svc, "banner": banner} for port, svc, banner in p["services"]],
        "lure_level": p["lure"],
    }


def deploy_decoy_host(profile: str, ip: str | None = None, hostname: str | None = None) -> str:
    """Cria e registra um host-isca convincente no espaço morto (honeynet).
    Se `ip` for omitido, aloca automaticamente um IP livre de uma honeynet
    declarada. Não toca em rede/firewall — só registra a mentira e prepara
    os banners para serem servidos (ver limitação 4B no topo do módulo)."""
    if profile not in _PROFILES:
        return f"Perfil de decoy desconhecido: {profile!r}. Opções: {', '.join(_PROFILES)}."

    if ip is None:
        ip = _allocate_decoy_ip()
        if ip is None:
            return (
                "Não há honeynet declarada (ou IP livre) para alocar o decoy. "
                "Declare um intervalo morto com honeynet.declare_range() primeiro "
                "— ex.: '10.50.0.0/28', 'segmento reservado, nunca usado'."
            )

    ok, reason = _is_safe_decoy_ip(ip)
    if not ok:
        return f"Recusado: {reason}"

    if ip in get_decoy_ips():
        return f"Já existe um decoy no IP {ip}."

    spec = generate_decoy_spec(profile, hostname=hostname)
    add_decoy_asset(
        spec["decoy_id"], spec["hostname"], ip, spec["os"], profile,
        json.dumps(spec["services"]), spec["lure_level"],
    )
    log_event(
        "decoy_deployed", None,
        f"decoy={spec['decoy_id']} host={spec['hostname']} ip={ip} profile={profile}",
        action_taken="isca declarada",
    )
    ports = ", ".join(str(s["port"]) for s in spec["services"])
    return (
        f"Host-isca '{spec['hostname']}' ({profile}) declarado em {ip} "
        f"[{spec['os']}], portas falsas {ports}, atratividade {spec['lure_level']}. "
        f"id={spec['decoy_id']}. Qualquer toque neste IP é ataque confirmado."
    )


def remove_decoy(decoy_id: str) -> str:
    if remove_decoy_asset(decoy_id):
        log_event("decoy_removed", None, f"decoy={decoy_id}", action_taken="removido")
        return f"Decoy {decoy_id} removido."
    return f"Nenhum decoy com id {decoy_id}."


# ---------- visão / mapa falso ----------

def _parse_services(services_json: str) -> list[dict]:
    try:
        return json.loads(services_json)
    except (json.JSONDecodeError, TypeError):
        return []


def describe_deception() -> str:
    """Mostra a mentira atualmente no ar: quais hosts-isca a Nexus declarou e
    se algum já foi consumido."""
    rows = list_decoy_assets()
    if not rows:
        return "Nenhum host-isca de deception ativa declarado ainda."
    lines = [f"DECEPTION ATIVA — {len(rows)} host(s)-isca no ar:"]
    for (decoy_id, hostname, ip, os, profile, services_json, lure, _created,
         consumed, last_consumed) in rows:
        svcs = _parse_services(services_json)
        ports = "/".join(str(s["port"]) for s in svcs)
        status = (
            f"CONSUMIDO {consumed}x (último {last_consumed})" if consumed
            else "ainda não tocado"
        )
        lines.append(
            f"  [{decoy_id}] {hostname} {ip} ({profile}, {os}) "
            f"portas {ports} — atratividade {lure} — {status}"
        )
    return "\n".join(lines)


def generate_deception_map() -> str:
    """Gera o DOCUMENTO de inventário falso que um atacante leria e acreditaria
    — estilo /etc/hosts + notas internas. É a 'informação falsa convincente'
    em si. Sirva-o como arquivo-isca (honeytokens.plant_decoy_file usa o mesmo
    espírito) para que abri-lo dispare o canário."""
    rows = list_decoy_assets()
    if not rows:
        return "# Nenhum decoy declarado — nada para mapear. Use deploy_decoy_host() antes."
    lines = [
        "# ====================================================",
        "# Inventário de rede interna — CONFIDENCIAL",
        "# Gerado pelo provisionamento automático. Não distribuir.",
        "# ====================================================",
        "",
        "# /etc/hosts (parcial)",
    ]
    for (_decoy_id, hostname, ip, _os, _profile, _svc, _lure, _c, _cc, _lc) in rows:
        lines.append(f"{ip}\t{hostname} {hostname.split('-')[0]}")
    lines.append("")
    lines.append("# Serviços conhecidos (do scan interno mais recente):")
    for (_decoy_id, hostname, ip, os, _profile, services_json, _lure, _c, _cc, _lc) in rows:
        svcs = _parse_services(services_json)
        svc_str = ", ".join(f"{s['port']}/{s['service']} ({s['banner']})" for s in svcs)
        lines.append(f"#  {hostname} ({ip}) [{os}]: {svc_str}")
    return "\n".join(lines)


# ---------- detecção de consumo (a mentira funcionou) ----------

def detect_deception_consumption() -> list[tuple[str, str, str]]:
    """Cruza os alertas de DPI já capturados contra os IPs-isca: se um alerta
    tem como DESTINO um decoy, alguém agiu sobre a informação falsa. Retorna
    [(atacante_ip, decoy_ip, hostname_falso)] e registra o consumo. Mesma
    mecânica da honeynet — presença sozinha já é o sinal."""
    rows = list_decoy_assets()
    if not rows:
        return []
    by_ip = {r[2]: r[1] for r in rows}  # ip -> hostname

    hits: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    consumed_ips: set[str] = set()
    for entry in dpi.get_alert_entries():
        src_ip, dest_ip = entry.get("src_ip"), entry.get("dest_ip")
        if dest_ip in by_ip and src_ip:
            key = (src_ip, dest_ip)
            if key in seen:
                continue
            seen.add(key)
            hits.append((src_ip, dest_ip, by_ip[dest_ip]))
            consumed_ips.add(dest_ip)

    for ip in consumed_ips:
        record_decoy_consumption(ip)
    return hits


def describe_deception_consumption() -> str:
    rows = list_decoy_assets()
    if not rows:
        return "Nenhum host-isca declarado — declare com deploy_decoy_host() primeiro."
    hits = detect_deception_consumption()
    if not hits:
        return (
            "Nenhum consumo de deception detectado nos alertas de DPI capturados. "
            "(Lembre: servir os banners ao vivo exige a camada de socket nos IPs-isca "
            "+ port mirroring — ver limitação 4B no módulo.)"
        )
    lines = [f"DECEPTION CONSUMIDA — {len(hits)} atacante(s) agiram sobre a rede falsa:"]
    for attacker, decoy_ip, hostname in hits:
        lines.append(f"  {attacker} -> tocou o host-isca {hostname} ({decoy_ip})")
    return "\n".join(lines)
