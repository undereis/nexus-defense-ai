"""Forense digital: análise de memória (Volatility 3) e do filesystem
(Sleuth Kit — fls/tsk_recover, o motor por trás do Autopsy).

Opera apenas sobre arquivos dentro de WORKDIR (mesma sandbox de
cracking.py/malware_analysis.py) — uma imagem de memória ou de disco é
exatamente o tipo de artefato sensível que nunca deve ser referenciado
por caminho arbitrário do sistema.

NUNCA VALIDADO CONTRA UMA IMAGEM REAL (memória ou disco) — não há
nenhuma disponível neste ambiente. Volatility3, fls e tsk_recover não
estão instalados aqui. A lógica de validação de path e construção de
comando está pronta e testada (mock de subprocess), mas o
comportamento real desses binários contra uma imagem de verdade nunca
foi confirmado. Antes de confiar nisso para um caso real, valide
manualmente com uma imagem de teste conhecida.
"""

import re
import shutil
import subprocess

from database.db import log_event
from tools.workdir import resolve_in_workdir

_TIMEOUT_SECONDS = 600
_PLUGIN_RE = re.compile(r"^[A-Za-z0-9_.]+$")

# Plugins mais usados do Volatility3 por categoria — não é a lista
# completa (`vol3 -h` lista todos), é um guia rápido para não precisar
# decorar a sintaxe `os.categoria.NomeDoPlugin`.
COMMON_VOLATILITY_PLUGINS = {
    "windows": [
        "windows.info", "windows.pslist", "windows.pstree", "windows.cmdline",
        "windows.netscan", "windows.malfind", "windows.dlllist", "windows.filescan",
        "windows.hashdump", "windows.registry.hivelist",
    ],
    "linux": [
        "linux.pslist", "linux.pstree", "linux.bash", "linux.netstat",
        "linux.lsmod", "linux.malfind", "linux.elfs",
    ],
    "mac": ["mac.pslist", "mac.pstree", "mac.netstat", "mac.bash"],
}


def _run(cmd: list[str], timeout: int = _TIMEOUT_SECONDS) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            cmd, returncode=-1, stdout="", stderr=f"Excedeu {timeout}s e foi interrompido."
        )


def list_volatility_plugins() -> str:
    """Lista os plugins mais comuns do Volatility3 por categoria, para
    referência rápida antes de chamar run_memory_analysis."""
    lines = ["Plugins comuns do Volatility3 (lista completa: `vol3 -h`):"]
    for category, plugins in COMMON_VOLATILITY_PLUGINS.items():
        lines.append(f"  {category}: {', '.join(plugins)}")
    return "\n".join(lines)


def run_memory_analysis(image_file: str, plugin: str) -> str:
    """Roda um plugin do Volatility3 contra uma imagem de memória em
    WORKDIR (ex: 'memdump.raw', 'memdump.vmem'). plugin no formato
    'windows.pslist', 'linux.bash' etc — ver list_volatility_plugins().
    Read-only: nunca modifica a imagem."""
    if not _PLUGIN_RE.match(plugin):
        return f"Nome de plugin inválido: {plugin!r}. Use o formato 'categoria.NomePlugin' (ex: windows.pslist)."
    try:
        image_path = resolve_in_workdir(image_file)
    except ValueError as exc:
        return str(exc)
    binary = shutil.which("vol3") or shutil.which("vol")
    if not binary:
        return (
            "Volatility3 não está instalado. Instale com: pip install volatility3 "
            "(ou 'brew install volatility3' se disponível). Sem isso, não há como "
            "analisar dump de memória."
        )
    if not image_path.exists():
        return f"Arquivo de imagem não encontrado em workdir/: {image_file}"

    log_event("forensics_memory_analysis", None, f"image={image_file} plugin={plugin}", action_taken="executando")
    result = _run([binary, "-f", str(image_path), plugin])
    log_event(
        "forensics_memory_analysis_done", None,
        f"image={image_file} plugin={plugin} returncode={result.returncode}", action_taken="concluido",
    )
    if result.returncode != 0:
        return f"Falha ao rodar {plugin} em {image_file}: {result.stderr.strip()}"
    return result.stdout.strip() or f"{plugin} não retornou saída para {image_file}."


def filesystem_timeline(image_file: str) -> str:
    """Gera uma timeline do filesystem de uma imagem de disco em WORKDIR
    usando o Sleuth Kit (fls -r -m), o mesmo motor por trás do Autopsy.
    Mostra arquivos criados/modificados/acessados/deletados em ordem
    cronológica — útil para reconstruir o que aconteceu num host
    comprometido. Read-only."""
    try:
        image_path = resolve_in_workdir(image_file)
    except ValueError as exc:
        return str(exc)
    if not shutil.which("fls"):
        return (
            "Sleuth Kit (fls) não está instalado. Instale com: brew install sleuthkit. "
            "Sem isso, não há como gerar timeline de filesystem a partir de uma imagem."
        )
    if not image_path.exists():
        return f"Arquivo de imagem não encontrado em workdir/: {image_file}"

    log_event("forensics_timeline", None, f"image={image_file}", action_taken="executando")
    result = _run(["fls", "-r", "-m", "/", str(image_path)])
    log_event(
        "forensics_timeline_done", None,
        f"image={image_file} returncode={result.returncode}", action_taken="concluido",
    )
    if result.returncode != 0:
        return f"Falha ao gerar timeline de {image_file}: {result.stderr.strip()}"
    lines = result.stdout.strip().splitlines()
    preview = "\n".join(lines[:200])
    more = f"\n... (+{len(lines) - 200} linha(s), saída truncada)" if len(lines) > 200 else ""
    return preview + more if preview else f"fls não retornou saída para {image_file}."


def recover_deleted_files(image_file: str, output_subdir: str) -> str:
    """Recupera arquivos deletados de uma imagem de disco em WORKDIR
    usando tsk_recover (Sleuth Kit), salvando em workdir/<output_subdir>/.
    Read-only sobre a imagem original — só escreve no diretório de saída."""
    try:
        image_path = resolve_in_workdir(image_file)
        output_path = resolve_in_workdir(output_subdir)
    except ValueError as exc:
        return str(exc)
    if not shutil.which("tsk_recover"):
        return (
            "Sleuth Kit (tsk_recover) não está instalado. Instale com: brew install sleuthkit. "
            "Sem isso, não há como recuperar arquivos deletados de uma imagem."
        )
    if not image_path.exists():
        return f"Arquivo de imagem não encontrado em workdir/: {image_file}"
    output_path.mkdir(parents=True, exist_ok=True)

    log_event("forensics_recover", None, f"image={image_file} output={output_subdir}", action_taken="executando")
    result = _run(["tsk_recover", "-a", str(image_path), str(output_path)])
    log_event(
        "forensics_recover_done", None,
        f"image={image_file} returncode={result.returncode}", action_taken="concluido",
    )
    if result.returncode != 0:
        return f"Falha ao recuperar arquivos de {image_file}: {result.stderr.strip()}"
    recovered = list(output_path.rglob("*"))
    files_only = [p for p in recovered if p.is_file()]
    return f"Recuperação concluída: {len(files_only)} arquivo(s) salvos em workdir/{output_subdir}/."
