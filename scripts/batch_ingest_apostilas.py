"""Processa em lote todos os PDFs novos em workdir/apostilas/, mapeando
cada arquivo para um tópico apropriado, usando o mesmo extrator/
normalizador de scripts/ingest_pdf.py."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.ingest_pdf import ingest_pdf

APOSTILAS_DIR = Path(__file__).resolve().parent.parent / "workdir" / "apostilas"

TOPIC_MAP = {
    "221345736-IP-Routing-Huawei.pdf": "huawei-routing",
    "368100193-Huawei-Configuraciones-Parte-2.pdf": "huawei-config",
    "368621195-Configurando-Olt-Huawei.pdf": "huawei-olt",
    "413471659-BAUSER-MTCRE-Treinamento-em-portugues-Brasil.pdf": "mikrotik-mtcre",
    "416424354-Comandos-Switch-y-Router-Cisco.pdf": "cisco-comandos",
    "441624054-cisco-certified-network-professional-security-sens.pdf": "cisco-ccnp-security",
    "454584538-huawei-u2000.pdf": "huawei-u2000",
    "478190923-Libro-Conexion-Redes-Lan-cisco.pdf": "cisco-redes-lan",
    "51362160-37222090-Huawei-WCDMA-HSDPA-Parameters-huawei.pdf": "huawei-wcdma",
    "515442776-Apostila-Fundamentos-GPON-Huawei.pdf": "huawei-gpon",
    "516909939-Tutorial-curso-Huawei.pdf": "huawei-tutorial",
    "580586669-Troubleshooting-OLT-Huawei.pdf": "huawei-olt",
    "623475063-MTCTCE.pdf": "mikrotik-mtctce",
    "631410247-MPLS-Huawei.pdf": "huawei-mpls",
    "696253615-HUAWEI-Commands.pdf": "huawei-commands",
    "831791569-MTCWE-2023-Com-CapsMan.pdf": "mikrotik-mtcwe",
}


def main():
    for filename, topic in TOPIC_MAP.items():
        path = APOSTILAS_DIR / filename
        if not path.exists():
            print(f"!! Arquivo não encontrado, pulando: {filename}")
            continue
        print(f"\n=== Processando {filename} (tópico: {topic}) ===")
        try:
            ingest_pdf(str(path), topic, pages_per_chunk=20)
        except Exception as exc:
            print(f"!! ERRO ao processar {filename}: {exc}")

    print("\n=== Lote concluído ===")


if __name__ == "__main__":
    main()
