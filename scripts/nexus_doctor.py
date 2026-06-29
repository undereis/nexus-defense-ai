"""Autodiagnóstico da Nexus (Frente F).

Roda o relatório de prontidão (núcleo, integrações, travas, operação NOC,
defesa ativa) e imprime. Lê o estado do .env/DB atuais.

Uso:
    venv/bin/python scripts/nexus_doctor.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.db import init_db  # noqa: E402
from tools import selftest  # noqa: E402


def main() -> int:
    init_db()
    print(selftest.run_selftest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
