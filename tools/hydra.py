"""Brute force de credenciais via Hydra.

Ação ativa contra um serviço ao vivo — pode causar bloqueio de conta ou
disparar alertas de IDS/IPS mesmo em alvo autorizado. Por isso usa o
mesmo toggle do Metasploit (ALLOW_ACTIVE_EXPLOITATION), e nunca uma
wordlist/usuário fora de workdir/.
"""

import re
import shutil
import subprocess

from config import ALLOW_ACTIVE_EXPLOITATION, HYDRA_TIMEOUT_SECONDS
from database.db import log_event
from tools.workdir import resolve_in_workdir

_HOST_RE = re.compile(r"^[A-Za-z0-9.\-:]+$")
_SIMPLE_RE = re.compile(r"^[\w.\-@]+$")
_FORM_PATH_RE = re.compile(r"^[\w\-./:^=&?%]+$")

SUPPORTED_SERVICES = {
    "ssh", "ftp", "telnet", "mysql", "postgres", "rdp", "smb", "vnc",
    "http-get", "http-post-form", "https-get", "https-post-form",
}


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            cmd, returncode=-1, stdout="", stderr=f"Excedeu {timeout}s e foi interrompido."
        )


def brute_force_login(
    target: str,
    service: str,
    username: str = "",
    userlist: str = "",
    password: str = "",
    wordlist: str = "",
    port: str = "",
    http_form_path: str = "",
) -> str:
    """Testa credenciais contra um serviço de um alvo autorizado. service
    deve ser um dos SUPPORTED_SERVICES. Informe username OU userlist (em
    workdir/), e password OU wordlist (em workdir/). Para http-post-form/
    http-get, http_form_path segue o formato do hydra (ex:
    '/login:user=^USER^&pass=^PASS^:F=incorrect')."""
    if not ALLOW_ACTIVE_EXPLOITATION:
        return (
            "Brute force está DESATIVADO. Para habilitar, defina "
            "ALLOW_ACTIVE_EXPLOITATION=true no .env — pode causar bloqueio "
            "de conta ou alertas no alvo, mesmo autorizado."
        )
    if not shutil.which("hydra"):
        return "hydra não está instalado. Rode: brew install hydra"

    target = target.strip()
    if not _HOST_RE.match(target):
        return f"Alvo inválido: {target}"
    if service not in SUPPORTED_SERVICES:
        return f"Serviço não suportado: {service}. Opções: {', '.join(sorted(SUPPORTED_SERVICES))}"

    cmd = ["hydra"]

    if username:
        if not _SIMPLE_RE.match(username):
            return f"Username inválido: {username}"
        cmd += ["-l", username]
    elif userlist:
        try:
            path = resolve_in_workdir(userlist)
        except ValueError as exc:
            return str(exc)
        if not path.is_file():
            return f"Lista de usuários não encontrada em workdir/: {userlist}"
        cmd += ["-L", str(path)]
    else:
        return "Informe username ou userlist."

    if password:
        cmd += ["-p", password]
    elif wordlist:
        try:
            path = resolve_in_workdir(wordlist)
        except ValueError as exc:
            return str(exc)
        if not path.is_file():
            return f"Wordlist não encontrada em workdir/: {wordlist}"
        cmd += ["-P", str(path)]
    else:
        return "Informe password ou wordlist."

    if port:
        if not port.isdigit():
            return f"Porta inválida: {port}"
        cmd += ["-s", port]

    cmd += ["-t", "4", "-f"]  # 4 threads, para no primeiro sucesso

    service_arg = service
    if service in ("http-get", "http-post-form", "https-get", "https-post-form"):
        if not http_form_path or not _FORM_PATH_RE.match(http_form_path):
            return (
                "Para serviços HTTP, http_form_path é obrigatório no formato "
                "hydra (ex: '/login:user=^USER^&pass=^PASS^:F=incorrect')."
            )
        service_arg = f"{service}"
        cmd += [target, service_arg, http_form_path]
    else:
        cmd += [target, service_arg]

    log_event("hydra_attempt", target, f"service={service} username={username or userlist}", action_taken="executando")
    result = _run(cmd, timeout=HYDRA_TIMEOUT_SECONDS)
    output = result.stdout.strip() or result.stderr.strip()
    found = "[" in output and "login:" in output.lower()
    log_event("hydra_result", target, f"service={service} found={found}", action_taken="concluido")

    return output or "Hydra não retornou saída."
