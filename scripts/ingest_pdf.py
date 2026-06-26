"""Extrai texto de um PDF (apostila/material próprio do criador) e ingere
na base de conhecimento local da Nexus, em blocos por página.

Uso:
    ./venv/bin/python scripts/ingest_pdf.py <caminho.pdf> <topico> [paginas_por_bloco]

Exemplo:
    ./venv/bin/python scripts/ingest_pdf.py workdir/apostilas/cisco_ccna.pdf cisco-ccna 20

Corrige automaticamente o efeito de "texto duplicado" comum em alguns PDFs
(cada caractere repetido devido a fonte em negrito sintético/fill+stroke),
sem arriscar corromper palavras com letras dobradas legítimas.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pdfplumber

from database.db import init_db
from tools.knowledge_base import ingest


def normalize_doubled_text(text: str) -> str:
    """Desfaz duplicação de caracteres só em tokens onde TODOS os
    caracteres estão em pares idênticos consecutivos — evita corromper
    palavras com letras dobradas legítimas (ex: "carro", "passo")."""
    def fix(tok: str) -> str:
        if len(tok) >= 2 and len(tok) % 2 == 0 and all(
            tok[i] == tok[i + 1] for i in range(0, len(tok), 2)
        ):
            return tok[0::2]
        return tok
    return re.sub(r"\S+", lambda m: fix(m.group(0)), text)


def ingest_pdf(pdf_path: str, topic: str, pages_per_chunk: int = 20):
    init_db()
    path = Path(pdf_path)
    source_url = f"arquivo local: {pdf_path}"

    with pdfplumber.open(path) as pdf:
        pages = [normalize_doubled_text(p.extract_text() or "") for p in pdf.pages]

    total = 0
    for start in range(0, len(pages), pages_per_chunk):
        end = min(start + pages_per_chunk, len(pages))
        chunk_text = "\n\n".join(pages[start:end]).strip()
        if not chunk_text:
            continue
        title = f"{path.stem} — páginas {start + 1}-{end}"
        print(ingest(topic, title, source_url, chunk_text))
        total += 1

    print(f"\nTotal: {total} bloco(s) ingerido(s) a partir de {len(pages)} página(s).")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    pdf_path = sys.argv[1]
    topic = sys.argv[2]
    pages_per_chunk = int(sys.argv[3]) if len(sys.argv) > 3 else 20
    ingest_pdf(pdf_path, topic, pages_per_chunk)
