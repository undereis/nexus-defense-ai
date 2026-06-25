"""Popula a base de conhecimento local com documentação técnica pública
oficial (RouterOS/Mikrotik, Cisco, Huawei, OWASP) curada manualmente.

Rodar uma vez por instalação nova: ./venv/bin/python scripts/seed_knowledge_base.py

Idempotente — não duplica documentos já ingeridos (verifica pelo título).
Para adicionar mais conteúdo depois, edite knowledge_seed_data.json ou use
a tool search_knowledge_base/ingest diretamente via chat com a Nexus.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.db import get_conn, init_db
from tools.knowledge_base import ingest

SEED_FILE = Path(__file__).resolve().parent / "knowledge_seed_data.json"


def _already_ingested(title: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM knowledge_documents WHERE title = ? LIMIT 1", (title,)
        ).fetchone()
        return row is not None


def main():
    init_db()
    docs = json.loads(SEED_FILE.read_text(encoding="utf-8"))

    added = 0
    skipped = 0
    for doc in docs:
        if _already_ingested(doc["title"]):
            skipped += 1
            continue
        print(ingest(doc["topic"], doc["title"], doc["source_url"], doc["content"]))
        added += 1

    print(f"\n{added} documento(s) adicionado(s), {skipped} já existiam.")


if __name__ == "__main__":
    main()
