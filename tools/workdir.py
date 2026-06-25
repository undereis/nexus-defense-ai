"""Confinamento de arquivos para as ferramentas de maior risco (cracking de
senha, análise de malware): tudo que a Nexus lê/escreve para essas tools
fica dentro de WORKDIR, nunca em qualquer caminho arbitrário do sistema —
isso impede que um path tipo "../../etc/passwd" escape para fora da área
destinada a essas operações."""

from pathlib import Path

from config import WORKDIR

WORKDIR.mkdir(parents=True, exist_ok=True)


def resolve_in_workdir(filename: str) -> Path:
    """Resolve um nome de arquivo relativo ao WORKDIR e garante que o
    caminho final continua dentro dele. Lança ValueError se escapar."""
    candidate = (WORKDIR / filename).resolve()
    try:
        candidate.relative_to(WORKDIR.resolve())
    except ValueError:
        raise ValueError(f"Caminho fora do diretório permitido: {filename}")
    return candidate
