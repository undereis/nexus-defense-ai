"""Cracking de senhas via Hashcat e John the Ripper.

Opera apenas sobre arquivos dentro de WORKDIR (workdir/) — o criador
coloca o arquivo de hashes lá antes de pedir o crack. Usado para testar
a força de senhas em hashes que o criador tem autorização para
analisar (ex: extraídos de um pentest autorizado, ou senhas próprias).
"""

import re
import shutil
import subprocess

from config import HASHCAT_TIMEOUT_SECONDS, JOHN_TIMEOUT_SECONDS
from database.db import log_event
from tools.workdir import resolve_in_workdir

_MODE_RE = re.compile(r"^\d+$")


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            cmd, returncode=-1, stdout="", stderr=f"Excedeu {timeout}s e foi interrompido."
        )


def crack_with_hashcat(hash_file: str, hash_mode: str, wordlist: str, attack_mode: str = "0") -> str:
    """Roda hashcat contra um arquivo de hash em WORKDIR usando uma wordlist
    também em WORKDIR. hash_mode é o código numérico do hashcat (ex: 0 para
    MD5, 1000 para NTLM, 1800 para sha512crypt — `hashcat --help` lista todos).
    attack_mode 0 = dicionário (padrão)."""
    if not _MODE_RE.match(hash_mode) or not _MODE_RE.match(attack_mode):
        return "hash_mode e attack_mode devem ser números (ver `hashcat --help`)."

    try:
        hash_path = resolve_in_workdir(hash_file)
        wordlist_path = resolve_in_workdir(wordlist)
    except ValueError as exc:
        return str(exc)
    if not hash_path.is_file():
        return f"Arquivo de hash não encontrado em workdir/: {hash_file}"
    if not wordlist_path.is_file():
        return f"Wordlist não encontrada em workdir/: {wordlist}"
    if not shutil.which("hashcat"):
        return "hashcat não está instalado. Rode: brew install hashcat"

    log_event("hashcat_attempt", None, f"hash_file={hash_file} mode={hash_mode}", action_taken="executando")

    run_result = _run(
        ["hashcat", "-m", hash_mode, "-a", attack_mode, "--runtime", str(HASHCAT_TIMEOUT_SECONDS),
         "--potfile-disable", "-o", str(hash_path) + ".cracked", str(hash_path), str(wordlist_path)],
        timeout=HASHCAT_TIMEOUT_SECONDS + 30,
    )

    cracked_file = hash_path.with_suffix(hash_path.suffix + ".cracked")
    cracked = cracked_file.read_text().strip() if cracked_file.exists() else ""

    log_event("hashcat_result", None, f"hash_file={hash_file} found={bool(cracked)}", action_taken="concluido")

    if cracked:
        return f"Senha(s) encontrada(s):\n{cracked}"
    if run_result.returncode == -1:
        return run_result.stderr
    return "Nenhuma senha encontrada com essa wordlist dentro do tempo limite.\n" + run_result.stdout[-500:]


_FORMAT_RE = re.compile(r"^[\w-]+$")


def crack_with_john(hash_file: str, wordlist: str = "", hash_format: str = "") -> str:
    """Roda John the Ripper contra um arquivo de hash em WORKDIR. Se
    wordlist for omitida, usa as regras padrão do John (modo 'single').
    hash_format é o --format do John (ex: 'raw-md5', 'nt', 'sha512crypt')
    — sem isso, o John tenta auto-detectar e pode escolher errado para
    hashes "crus" sem prefixo identificador; se a primeira tentativa não
    encontrar nada, tente de novo informando o formato explicitamente."""
    try:
        hash_path = resolve_in_workdir(hash_file)
    except ValueError as exc:
        return str(exc)
    if not hash_path.is_file():
        return f"Arquivo de hash não encontrado em workdir/: {hash_file}"
    if hash_format and not _FORMAT_RE.match(hash_format):
        return f"hash_format inválido: {hash_format!r}"
    if not shutil.which("john"):
        return "john não está instalado. Rode: brew install john-jumbo"

    cmd = ["john", f"--max-run-time={JOHN_TIMEOUT_SECONDS}"]
    if hash_format:
        cmd.append(f"--format={hash_format}")
    if wordlist:
        try:
            wordlist_path = resolve_in_workdir(wordlist)
        except ValueError as exc:
            return str(exc)
        if not wordlist_path.is_file():
            return f"Wordlist não encontrada em workdir/: {wordlist}"
        cmd.append(f"--wordlist={wordlist_path}")
    cmd.append(str(hash_path))

    log_event("john_attempt", None, f"hash_file={hash_file} format={hash_format}", action_taken="executando")
    _run(cmd, timeout=JOHN_TIMEOUT_SECONDS + 30)

    show_cmd = ["john", "--show"]
    if hash_format:
        show_cmd.append(f"--format={hash_format}")
    show_cmd.append(str(hash_path))
    show_result = _run(show_cmd, timeout=30)
    log_event("john_result", None, f"hash_file={hash_file}", action_taken="concluido")

    return show_result.stdout.strip() or (
        "Nenhuma senha encontrada com essa configuração. Se o hash é 'cru' "
        "(sem prefixo, ex: só o MD5/NTLM em si), tente de novo passando "
        "hash_format explicitamente (ex: 'raw-md5', 'nt')."
    )
