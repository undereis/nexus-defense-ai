"""Modelo de risco por cliente (Fase 7, item 3).

Agrega o histórico de comportamento suspeito de CADA cliente da Xfiber (pelo
seu bloco CIDR) num score de risco e num tier (baixo/médio/alto). Clientes que
historicamente geram tráfego malicioso passam a ser monitorados de forma mais
agressiva AUTOMATICAMENTE — o z-threshold da detecção de anomalia daquele
cliente baixa conforme o risco, então um desvio menor já dispara alerta.

Sinais (todos JÁ persistidos, nada novo a coletar):
  - reputação dos IPs do CIDR na memória de atacantes (threat_intel:
    sinalizações + isolamentos, via reputation_score);
  - atividade de honeypot vinda do CIDR (tocar honeypot = malicioso por
    definição — não há tráfego legítimo para uma armadilha);
  - IPs do CIDR atualmente bloqueados no firewall.

Stateless por design: o risco é recalculado sob demanda a partir dos sinais
persistidos, então está sempre atualizado — não há score velho em cache.

Os pesos são uma heurística explicável (não ML), documentada abaixo. Combina
com tools/client_baseline.py (volume) e tools/anomaly.py (global).
"""

import ipaddress

from database.db import (
    get_client_profile,
    get_honeypot_hit_counts_by_ip,
    list_blocked_ips,
    list_client_profiles,
    list_repeat_offenders,
)
from tools.client_baseline import DEFAULT_Z_THRESHOLD
from tools.threat_intel import reputation_score

# Pesos da heurística de risco.
_W_HONEYPOT_IP = 15      # cada IP distinto do cliente que tocou honeypot
_W_HONEYPOT_HIT = 1      # cada hit individual de honeypot
_W_BLOCKED_IP = 5        # cada IP do cliente atualmente bloqueado
# (reputação já vem pré-ponderada por reputation_score: isolado*10 + flag*2)

# Faixas de tier por score.
_TIER_MEDIO_MIN = 1
_TIER_ALTO_MIN = 20

# Quanto o z-threshold baixa por tier (monitoramento mais agressivo).
_Z_DELTA = {"alto": 1.0, "médio": 0.5, "baixo": 0.0}
_Z_FLOOR = 1.5           # nunca deixar a detecção absurdamente sensível


def _client_networks() -> list[tuple[str, "ipaddress._BaseNetwork"]]:
    """(client_id, network) de todos os clientes com CIDR válido."""
    nets = []
    for client_id, cidr, *_ in list_client_profiles():
        try:
            nets.append((client_id, ipaddress.ip_network(cidr, strict=False)))
        except ValueError:
            continue
    return nets


def _ip_in(net, ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def risk_tier(score: int) -> str:
    if score >= _TIER_ALTO_MIN:
        return "alto"
    if score >= _TIER_MEDIO_MIN:
        return "médio"
    return "baixo"


def compute_client_risk(client_id: str) -> dict | None:
    """Calcula o risco de um cliente a partir dos sinais persistidos.
    Retorna dict (score, tier, componentes) ou None se o cliente não existe."""
    profile = get_client_profile(client_id)
    if not profile:
        return None
    cidr = profile[1]
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None

    # Reputação dos IPs do CIDR (threat_intel).
    reputation_sum = 0
    rep_ips = 0
    for ip, times_flagged, times_isolated, _last in list_repeat_offenders(0):
        if _ip_in(net, ip):
            reputation_sum += reputation_score(times_flagged, times_isolated)
            rep_ips += 1

    # Honeypot vindo do CIDR.
    hp_ips = 0
    hp_hits = 0
    for ip, count in get_honeypot_hit_counts_by_ip():
        if _ip_in(net, ip):
            hp_ips += 1
            hp_hits += count

    # IPs do CIDR atualmente bloqueados.
    blocked_ips = sum(1 for ip, *_ in list_blocked_ips() if _ip_in(net, ip))

    score = (
        reputation_sum
        + hp_ips * _W_HONEYPOT_IP
        + hp_hits * _W_HONEYPOT_HIT
        + blocked_ips * _W_BLOCKED_IP
    )
    return {
        "client_id": client_id,
        "cidr": cidr,
        "score": score,
        "tier": risk_tier(score),
        "reputation_sum": reputation_sum,
        "reputation_ips": rep_ips,
        "honeypot_ips": hp_ips,
        "honeypot_hits": hp_hits,
        "blocked_ips": blocked_ips,
    }


def adjusted_z_threshold(client_id: str,
                         base: float = DEFAULT_Z_THRESHOLD) -> float:
    """z-threshold de anomalia ajustado ao risco do cliente: quanto mais
    arriscado, mais sensível (menor). Cliente desconhecido ou de baixo risco
    usa o base. Nunca abaixo do piso de segurança. Esta é a porta pela qual o
    'monitoramento mais agressivo automático' entra no monitor_loop."""
    risk = compute_client_risk(client_id)
    tier = risk["tier"] if risk else "baixo"
    return max(_Z_FLOOR, base - _Z_DELTA.get(tier, 0.0))


def describe_client_risk(client_id: str) -> str:
    """Relatório textual do risco de um cliente, para a tool do agente."""
    risk = compute_client_risk(client_id)
    if risk is None:
        return (
            f"Cliente '{client_id}' não encontrado. "
            "Cadastre com add_client_profile."
        )
    z = adjusted_z_threshold(client_id)
    tier_label = {"alto": "ALTO", "médio": "médio", "baixo": "baixo"}[risk["tier"]]
    return (
        f"Risco do cliente '{client_id}' ({risk['cidr']}): {tier_label} "
        f"(score {risk['score']}).\n"
        f"  Reputação acumulada: {risk['reputation_sum']} "
        f"({risk['reputation_ips']} IP(s) com histórico)\n"
        f"  Honeypot: {risk['honeypot_ips']} IP(s), {risk['honeypot_hits']} hit(s)\n"
        f"  Bloqueados agora: {risk['blocked_ips']} IP(s)\n"
        f"  Monitoramento: z-threshold ajustado para {z} "
        f"(base {DEFAULT_Z_THRESHOLD}) — "
        + ("mais agressivo." if z < DEFAULT_Z_THRESHOLD else "padrão.")
    )


def rank_clients_by_risk() -> str:
    """Ranqueia todos os clientes cadastrados por score de risco (desc)."""
    profiles = list_client_profiles()
    if not profiles:
        return "Nenhum cliente cadastrado. Use add_client_profile para começar."
    risks = [compute_client_risk(p[0]) for p in profiles]
    risks = [r for r in risks if r is not None]
    risks.sort(key=lambda r: r["score"], reverse=True)
    lines = [f"Risco por cliente ({len(risks)}), do maior para o menor:"]
    for r in risks:
        lines.append(
            f"  [{r['tier'].upper():5}] {r['client_id']} ({r['cidr']}) "
            f"— score {r['score']} "
            f"(rep {r['reputation_sum']}, honeypot {r['honeypot_ips']}ip/"
            f"{r['honeypot_hits']}hit, bloq {r['blocked_ips']})"
        )
    return "\n".join(lines)
