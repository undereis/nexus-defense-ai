"""Simulador de tráfego sintético (Frente G).

Boa parte da máquina de detecção/aprendizado da Nexus (baseline z-score
clássico + robusto, maturidade dos 168 slots semanais, auto-tune, risco por
cliente) só "ganha vida" depois de semanas de tráfego real. Este módulo gera
tráfego sintético realista (curva diurna de ISP + ruído) para EXERCITAR e
DEMONSTRAR essa máquina agora — validar que ela funciona, sem esperar dados
reais. É ferramenta de dev/validação: popula as MESMAS tabelas que o
monitor_loop popularia (traffic_baseline_samples, client_traffic_samples).

Determinístico por `seed` — testável e reproduzível.
"""

import random
from datetime import datetime, timedelta, timezone

from database.db import record_client_traffic_sample
from tools import anomaly, client_baseline

# Curva diurna típica de ISP: fração do pico por hora do dia (0-23). Madrugada
# baixa, leve subida de manhã, platô à tarde, pico no começo da noite.
_DIURNAL = [
    0.25, 0.18, 0.12, 0.10, 0.10, 0.12,   # 0-5  madrugada
    0.20, 0.35, 0.50, 0.55, 0.55, 0.55,   # 6-11 manhã
    0.60, 0.60, 0.58, 0.58, 0.62, 0.70,   # 12-17 tarde
    0.85, 1.00, 0.98, 0.85, 0.60, 0.40,   # 18-23 pico noturno
]


def expected_connections(hour: int, peak: float) -> float:
    """Volume esperado de conexões numa hora do dia, dado o pico diário."""
    return peak * _DIURNAL[hour % 24]


def simulate_baseline(weeks: int = 6, peak: int = 300,
                      clients: list[tuple[str, str]] | None = None,
                      now: datetime | None = None, seed: int = 42,
                      jitter: float = 0.12) -> dict:
    """Grava `weeks` semanas de amostras (uma por hora, retroativas) seguindo a
    curva diurna + ruído gaussiano, na baseline global e — se `clients` for uma
    lista de (client_id, cidr) — também por cliente. weeks>=5 deixa todos os 168
    slots semanais 'prontos' (>= MIN_SAMPLES_FOR_BASELINE). Retorna um resumo."""
    rng = random.Random(seed)
    now = now or datetime.now(timezone.utc)
    clients = clients or []
    for cid, cidr in clients:
        client_baseline.add_client_profile(cid, cidr, "simulado")

    client_peak = peak / (2 * max(1, len(clients))) if clients else 0
    n_global = n_client = 0
    total_hours = weeks * 7 * 24
    for h in range(total_hours):
        ts = now - timedelta(hours=h)
        base = expected_connections(ts.hour, peak)
        total = max(0, int(rng.gauss(base, base * jitter)))
        distinct = max(1, int(total / rng.uniform(1.5, 3.0)))
        anomaly.record_current_sample(total, distinct, ts)
        n_global += 1
        for cid, _cidr in clients:
            cbase = expected_connections(ts.hour, client_peak)
            ctotal = max(0, int(rng.gauss(cbase, cbase * jitter)))
            record_client_traffic_sample(cid, ts.hour, ts.weekday(), ctotal, max(1, ctotal // 2))
            n_client += 1

    return {
        "weeks": weeks, "peak": peak,
        "global_samples": n_global, "client_samples": n_client,
        "clients": [c for c, _ in clients],
    }


def demo_detection(now: datetime | None = None, peak: int = 300) -> dict:
    """Sobre a baseline já simulada, dispara um pico óbvio no slot atual e
    devolve o veredito do detector — para demonstrar que a anomalia é pega.
    Assume que simulate_baseline rodou antes com o mesmo `peak`/`now`."""
    now = now or datetime.now(timezone.utc)
    spike_value = int(expected_connections(now.hour, peak) * 8) + 1
    return anomaly.check_anomaly(spike_value, now)


def describe_simulation(weeks: int = 6, peak: int = 300,
                        clients: list[tuple[str, str]] | None = None,
                        now: datetime | None = None) -> str:
    """Roda a simulação e devolve um relatório antes/depois (maturidade) + a
    demonstração de detecção de pico. Para o script/CLI e diagnóstico."""
    now = now or datetime.now(timezone.utc)
    lines = ["═══ SIMULAÇÃO DE TRÁFEGO ═══", ""]
    lines.append("ANTES:")
    lines.append("  " + anomaly.baseline_maturity_report().replace("\n", "\n  "))
    summary = simulate_baseline(weeks=weeks, peak=peak, clients=clients, now=now)
    lines.append("")
    lines.append(f"Geradas {summary['global_samples']} amostras globais"
                 + (f" + {summary['client_samples']} por cliente ({', '.join(summary['clients'])})"
                    if summary["clients"] else "") + f" ({weeks} semanas).")
    lines.append("")
    lines.append("DEPOIS:")
    lines.append("  " + anomaly.baseline_maturity_report().replace("\n", "\n  "))
    lines.append("")
    spike = demo_detection(now=now, peak=peak)
    verdict = "DETECTADO ✅" if spike.get("is_anomaly") else "não detectado ❌"
    lines.append(f"Demo de pico no slot atual: {verdict} "
                 f"(z-score clássico {spike.get('z_score')}, robusto {spike.get('robust_z_score')}).")
    return "\n".join(lines)
