"""Simulador de tráfego sintético (Frente G) — exercita/valida a detecção.

Gera semanas de tráfego realista na baseline (global + por cliente), mostra a
maturidade antes/depois e demonstra a detecção de um pico. Útil para ver a
máquina de detecção funcionando sem esperar tráfego real.

ATENÇÃO: grava amostras no nexus.db apontado pela config. Use num banco de
dev/teste, não no de produção com histórico real.

Uso:
    venv/bin/python scripts/simulate_traffic.py --weeks 6
    venv/bin/python scripts/simulate_traffic.py --weeks 6 --clients "cliente-a:203.0.113.0/24,cliente-b:198.51.100.0/24"
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.db import init_db  # noqa: E402
from tools import traffic_sim  # noqa: E402


def _parse_clients(spec: str) -> list[tuple[str, str]]:
    out = []
    for entry in (spec or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        cid, _, cidr = entry.partition(":")
        if cid and cidr:
            out.append((cid.strip(), cidr.strip()))
    return out


def main() -> int:
    p = argparse.ArgumentParser(description="Simulador de tráfego sintético (Nexus).")
    p.add_argument("--weeks", type=int, default=6, help="semanas de baseline (>=5 deixa 168/168)")
    p.add_argument("--peak", type=int, default=300, help="pico diário de conexões")
    p.add_argument("--clients", default="", help="'id:cidr,id:cidr' para baseline por cliente")
    args = p.parse_args()

    init_db()
    print(traffic_sim.describe_simulation(
        weeks=args.weeks, peak=args.peak, clients=_parse_clients(args.clients)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
