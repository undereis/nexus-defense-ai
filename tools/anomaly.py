"""Detecção de anomalia por baseline estatístico (z-score).

O monitor de DDoS (tools/network_monitor.py) detecta por threshold fixo
("mais de N conexões do mesmo IP") — simples, mas não sabe o que é
"normal" para a SUA rede em cada horário. Às 3h da manhã, 20 conexões
pode ser um ataque; às 20h num provedor, pode ser tráfego normal.

Isto aprende o padrão real ao longo do tempo: para cada combinação de
hora do dia (0-23) e dia da semana, guarda amostras de volume total de
tráfego, calcula média e desvio padrão, e sinaliza quando o volume atual
se desvia muito do que já foi observado naquele mesmo horário antes.

Isso é estatística (z-score), não uma rede neural — é honesto chamar
isso de "aprende o padrão normal e detecta desvio", que é exatamente o
que foi pedido, mas não é o que a maioria das pessoas imagina quando
ouve "machine learning". Funciona com poucas dependências (só
statistics da stdlib) e fica mais preciso com o tempo, conforme mais
amostras se acumulam — não tem valor real nos primeiros dias de uso,
precisa de histórico (idealmente algumas semanas, cobrindo os mesmos
horários várias vezes) para a baseline significar algo.
"""

import statistics
from datetime import datetime, timezone

from database.db import count_traffic_samples, get_traffic_samples_for_slot, record_traffic_sample

MIN_SAMPLES_FOR_BASELINE = 5
DEFAULT_Z_SCORE_THRESHOLD = 3.0


def record_current_sample(total_connections: int, distinct_ips: int, now: datetime | None = None) -> None:
    """Registra uma amostra do volume de tráfego atual, marcada pelo
    horário real. Chamado periodicamente pelo monitor de rede."""
    now = now or datetime.now(timezone.utc)
    record_traffic_sample(now.hour, now.weekday(), total_connections, distinct_ips)


def _baseline_stats(hour_of_day: int, day_of_week: int) -> tuple[float, float, int] | None:
    rows = get_traffic_samples_for_slot(hour_of_day, day_of_week)
    if len(rows) < MIN_SAMPLES_FOR_BASELINE:
        return None
    totals = [r[0] for r in rows]
    mean = statistics.mean(totals)
    stdev = statistics.stdev(totals) if len(totals) > 1 else 0.0
    return mean, stdev, len(rows)


def check_anomaly(
    total_connections: int, now: datetime | None = None, z_threshold: float = DEFAULT_Z_SCORE_THRESHOLD
) -> dict:
    """Compara o volume atual com a baseline aprendida para o mesmo
    horário/dia da semana. Retorna dict com is_anomaly, z_score, mean,
    stdev, samples_used — ou is_anomaly=False com motivo='baseline
    insuficiente' se ainda não há histórico suficiente para esse slot."""
    now = now or datetime.now(timezone.utc)
    stats = _baseline_stats(now.hour, now.weekday())
    if stats is None:
        return {
            "is_anomaly": False,
            "reason": "baseline insuficiente para este horário (precisa de mais amostras históricas)",
            "samples_used": 0,
        }

    mean, stdev, n = stats
    if stdev == 0:
        # Sem variação histórica nenhuma: qualquer desvio do valor fixo já é notável.
        z_score = float("inf") if total_connections != mean else 0.0
    else:
        z_score = (total_connections - mean) / stdev

    return {
        "is_anomaly": z_score >= z_threshold,
        "z_score": round(z_score, 2) if z_score != float("inf") else z_score,
        "mean": round(mean, 1),
        "stdev": round(stdev, 1),
        "samples_used": n,
        "current": total_connections,
    }


def describe_anomaly_status(total_connections: int, now: datetime | None = None) -> str:
    """Versão em texto de check_anomaly, para a tool do agente."""
    total_samples = count_traffic_samples()
    result = check_anomaly(total_connections, now)

    if result["samples_used"] == 0:
        return (
            f"Ainda não há baseline suficiente para este horário específico "
            f"({total_samples} amostra(s) coletada(s) no total até agora). "
            "A detecção por z-score fica útil depois de alguns dias/semanas de uso real, "
            "cobrindo os mesmos horários repetidas vezes."
        )

    status = "ANOMALIA DETECTADA" if result["is_anomaly"] else "dentro do padrão normal"
    return (
        f"Tráfego atual: {result['current']} conexões — {status}.\n"
        f"Baseline deste horário: média={result['mean']}, desvio padrão={result['stdev']} "
        f"(baseado em {result['samples_used']} amostra(s) históricas).\n"
        f"Z-score: {result['z_score']}"
    )
