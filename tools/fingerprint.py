"""Fingerprint comportamental de atacante: mesma sequência de portas e
timing entre conexões pode indicar o MESMO atacante/ferramenta, mesmo
que ele troque de IP (proxy, botnet, IP dinâmico).

Usa só dados que o honeypot já registra (porta, serviço, timestamp de
cada conexão) — não inventa nenhuma fonte nova. A comparação é
puramente determinística (sequência de portas + intervalo entre
conexões), não é "IA reconhecendo padrão" — é fingerprinting clássico,
o mesmo princípio usado por ferramentas como p0f, só que sobre o
comportamento de varredura em vez de pilha TCP/IP.

Honesto sobre limitações:
- Com poucas conexões por IP (1-2 hits), o fingerprint não é
  discriminante — qualquer dois atacantes aleatórios vão "parecer
  iguais" por falta de dados.
- honeypot_hits grava o timestamp com resolução de 1 SEGUNDO
  (datetime('now') do SQLite) — varreduras automatizadas reais costumam
  ser sub-segundo entre portas, então o componente de timing do score
  é mais grosseiro do que o ideal. O componente de sequência de portas
  (peso maior) não tem essa limitação.
"""

from database.db import (
    get_distinct_honeypot_ips_since,
    get_honeypot_hits_chronological_for_ip,
)

MIN_HITS_FOR_RELIABLE_FINGERPRINT = 3
DEFAULT_SIMILARITY_THRESHOLD = 0.75


def _parse_ts(ts: str):
    from datetime import datetime
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def compute_fingerprint(ip: str) -> dict:
    """Constrói o fingerprint de um IP: sequência ordenada de portas
    tocadas e os intervalos (em segundos) entre conexões consecutivas."""
    hits = get_honeypot_hits_chronological_for_ip(ip)
    ports = [h[0] for h in hits]
    timestamps = [_parse_ts(h[2]) for h in hits]
    intervals = []
    for a, b in zip(timestamps, timestamps[1:]):
        if a is not None and b is not None:
            intervals.append((b - a).total_seconds())
    return {"ip": ip, "port_sequence": ports, "intervals": intervals, "total_hits": len(hits)}


def _port_sequence_similarity(seq_a: list[int], seq_b: list[int]) -> float:
    """Similaridade de sequência: maior subsequência comum / tamanho da
    maior sequência. 1.0 = sequência idêntica, 0.0 = nada em comum."""
    if not seq_a or not seq_b:
        return 0.0
    n, m = len(seq_a), len(seq_b)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            if seq_a[i - 1] == seq_b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
    lcs = dp[n][m]
    return lcs / max(n, m)


def _timing_similarity(intervals_a: list[float], intervals_b: list[float], tolerance_pct: float = 0.4) -> float:
    """Similaridade de timing: compara o intervalo médio entre conexões.
    Sem intervalos suficientes (0 ou 1 conexão), não dá pra comparar
    timing — retorna 0.5 (neutro, nem ajuda nem prejudica o score)."""
    if not intervals_a or not intervals_b:
        return 0.5
    avg_a = sum(intervals_a) / len(intervals_a)
    avg_b = sum(intervals_b) / len(intervals_b)
    if avg_a == 0 and avg_b == 0:
        return 1.0
    larger = max(avg_a, avg_b) or 1.0
    diff_ratio = abs(avg_a - avg_b) / larger
    return max(0.0, 1.0 - diff_ratio / tolerance_pct) if diff_ratio <= tolerance_pct else 0.0


def compare_fingerprints(fp_a: dict, fp_b: dict) -> float:
    """Score de similaridade 0.0-1.0 entre dois fingerprints, combinando
    sequência de portas (peso maior, é o sinal mais forte) e timing."""
    port_sim = _port_sequence_similarity(fp_a["port_sequence"], fp_b["port_sequence"])
    timing_sim = _timing_similarity(fp_a["intervals"], fp_b["intervals"])
    return round(port_sim * 0.7 + timing_sim * 0.3, 3)


def find_similar_attackers(
    ip: str, hours: float = 24 * 7, threshold: float = DEFAULT_SIMILARITY_THRESHOLD
) -> list[tuple[str, float]]:
    """Compara o fingerprint de um IP contra todos os outros IPs que
    tocaram honeypot nas últimas N horas. Retorna [(ip_similar, score)],
    ordenado por score decrescente — candidatos a 'mesmo atacante, IP
    diferente'."""
    target_fp = compute_fingerprint(ip)
    if target_fp["total_hits"] < MIN_HITS_FOR_RELIABLE_FINGERPRINT:
        return []

    matches = []
    for other_ip in get_distinct_honeypot_ips_since(hours):
        if other_ip == ip:
            continue
        other_fp = compute_fingerprint(other_ip)
        if other_fp["total_hits"] < MIN_HITS_FOR_RELIABLE_FINGERPRINT:
            continue
        score = compare_fingerprints(target_fp, other_fp)
        if score >= threshold:
            matches.append((other_ip, score))
    return sorted(matches, key=lambda m: -m[1])


def describe_similar_attackers(ip: str, hours: float = 24 * 7) -> str:
    fp = compute_fingerprint(ip)
    if fp["total_hits"] < MIN_HITS_FOR_RELIABLE_FINGERPRINT:
        return (
            f"{ip} tem só {fp['total_hits']} conexão(ões) em honeypot — fingerprint "
            f"não confiável com menos de {MIN_HITS_FOR_RELIABLE_FINGERPRINT} hits."
        )
    matches = find_similar_attackers(ip, hours)
    if not matches:
        return f"Nenhum outro IP com fingerprint comportamental similar a {ip} nas últimas {hours:g}h."
    lines = [f"IPs com comportamento similar a {ip} (possível mesmo atacante, IP diferente):"]
    for other_ip, score in matches:
        lines.append(f"  {other_ip} — similaridade {score:.0%}")
    return "\n".join(lines)
