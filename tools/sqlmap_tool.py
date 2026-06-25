"""Injeção SQL automatizada via SQLMap.

Mais agressivo que tools/web_injection.py (que só faz probes manuais):
o SQLMap pode efetivamente extrair dados se encontrar a vulnerabilidade,
por isso usa o mesmo toggle de ação ativa do Metasploit/Hydra. Roda em
modo bateria (--batch, sem prompt interativo) com nível/risco moderados
por padrão para não ser destrutivo demais.
"""

import re
import shutil
import subprocess

from config import ALLOW_ACTIVE_EXPLOITATION, SQLMAP_TIMEOUT_SECONDS
from database.db import record_finding, log_event

_URL_RE = re.compile(r"^https?://[\w.\-:/%?=&]+$", re.IGNORECASE)


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            cmd, returncode=-1, stdout="", stderr=f"Excedeu {timeout}s e foi interrompido."
        )


def run_sqlmap(url: str, param: str = "", level: str = "1", risk: str = "1") -> str:
    """Roda sqlmap contra uma URL (com query string incluída, ex:
    'https://alvo.com/page?id=1') para detectar e, se encontrar, confirmar
    injeção SQL. param restringe o teste a um parâmetro específico. level
    (1-5) e risk (1-3) controlam agressividade — padrão conservador."""
    if not ALLOW_ACTIVE_EXPLOITATION:
        return (
            "SQLMap está DESATIVADO. Para habilitar, defina "
            "ALLOW_ACTIVE_EXPLOITATION=true no .env — pode extrair dados "
            "reais se encontrar a vulnerabilidade, mesmo em alvo autorizado."
        )
    if not shutil.which("sqlmap"):
        return "sqlmap não está instalado. Rode: brew install sqlmap"

    if not _URL_RE.match(url.strip()):
        return f"URL inválida: {url}"
    if not level.isdigit() or not (1 <= int(level) <= 5):
        return "level deve ser entre 1 e 5."
    if not risk.isdigit() or not (1 <= int(risk) <= 3):
        return "risk deve ser entre 1 e 3."

    cmd = ["sqlmap", "-u", url, "--batch", "--level", level, "--risk", risk]
    if param:
        if not re.match(r"^[\w\-]+$", param):
            return f"Parâmetro inválido: {param}"
        cmd += ["-p", param]

    log_event("sqlmap_attempt", url, f"param={param} level={level} risk={risk}", action_taken="executando")
    result = _run(cmd, timeout=SQLMAP_TIMEOUT_SECONDS)
    output = result.stdout.strip() or result.stderr.strip()

    vulnerable = "is vulnerable" in output.lower() or "parameter" in output.lower() and "injectable" in output.lower()
    log_event("sqlmap_result", url, f"vulnerable={vulnerable}", action_taken="concluido")
    record_finding(url, "sqlmap", output[-3000:])

    return output or "SQLMap não retornou saída."
