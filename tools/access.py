"""Acesso direto a hosts de teste: HTTP (curl), checagem de porta SSH e
execução de comandos remotos via SSH.

Tudo aqui é de alto impacto se usado contra hosts não autorizados — só
deve ser usado nos IPs/domínios de teste que o criador confirmou ter
autorização para acessar. Toda execução de comando remoto é registrada
em database/events para auditoria.
"""

import re
import socket
import subprocess

import requests

from config import SSH_ALLOWED_PATTERNS, SSH_KEY_PATH, SSH_USER
from database.db import log_event

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*$"
)
_ALLOWED_COMMAND_RE = [re.compile(p) for p in SSH_ALLOWED_PATTERNS]


def _is_command_allowed(command: str) -> bool:
    command = command.strip()
    return any(p.match(command) for p in _ALLOWED_COMMAND_RE)


def _validate_host(host: str) -> str:
    host = host.strip()
    if not _HOSTNAME_RE.match(host):
        raise ValueError(f"Host inválido: {host}")
    return host


def http_probe(url: str) -> str:
    """Equivalente a `curl <url>`: faz uma requisição HTTP e retorna status,
    headers principais e um trecho do corpo da resposta."""
    target = url if url.startswith("http") else f"http://{url}"
    try:
        resp = requests.get(target, timeout=10, allow_redirects=True)
    except requests.RequestException as exc:
        return f"Falha ao acessar {target}: {exc}"

    body_preview = resp.text[:1000]
    lines = [
        f"GET {target} -> {resp.status_code} {resp.reason}",
        f"Servidor: {resp.headers.get('Server', 'desconhecido')}",
        f"Content-Type: {resp.headers.get('Content-Type', 'desconhecido')}",
        "",
        "Corpo (primeiros 1000 chars):",
        body_preview,
    ]
    return "\n".join(lines)


def check_ssh_port(host: str, port: int = 22) -> str:
    """Verifica se a porta SSH está aberta e captura o banner do serviço,
    sem autenticar nem executar nada no host remoto."""
    host = _validate_host(host)
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            sock.settimeout(3)
            try:
                banner = sock.recv(256).decode(errors="replace").strip()
            except socket.timeout:
                banner = "(porta aberta, sem banner recebido a tempo)"
        return f"SSH em {host}:{port} está ABERTO. Banner: {banner}"
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return f"SSH em {host}:{port} não respondeu: {exc}"


def ssh_run_command(host: str, command: str, user: str = "", port: int = 22) -> str:
    """Executa um único comando remoto via SSH em um host de teste autorizado,
    usando autenticação por chave (sem senha, sem prompt interativo). Requer
    SSH_USER e SSH_KEY_PATH configurados no .env caso `user` não seja informado.
    Toda execução é registrada em database/events para auditoria."""
    host = _validate_host(host)
    if not _is_command_allowed(command):
        log_event("ssh_command_blocked", host, f"command={command!r}", action_taken="bloqueado")
        return (
            f"Comando bloqueado pela allowlist: '{command}'. Só comandos de diagnóstico "
            "read-only são permitidos por padrão (docker ps, systemctl status, uptime, df -h, "
            "etc). Para liberar outro padrão, adicione um regex em SSH_EXTRA_ALLOWED_PATTERNS no .env."
        )
    ssh_user = user or SSH_USER
    if not ssh_user:
        return "Nenhum usuário SSH configurado. Defina SSH_USER no .env ou informe o parâmetro 'user'."
    if not SSH_KEY_PATH:
        return "Nenhuma chave SSH configurada. Defina SSH_KEY_PATH no .env."

    cmd = [
        "ssh",
        "-i", SSH_KEY_PATH,
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        "-p", str(port),
        f"{ssh_user}@{host}",
        command,
    ]

    log_event("ssh_command", host, f"user={ssh_user} command={command!r}", action_taken="executando")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        log_event("ssh_command", host, f"command={command!r}", action_taken="timeout")
        return f"Comando excedeu 60s e foi interrompido: {command}"

    log_event(
        "ssh_command",
        host,
        f"command={command!r} returncode={result.returncode}",
        action_taken="concluido",
    )

    if result.returncode != 0:
        return f"Comando falhou (exit {result.returncode}):\n{result.stderr.strip() or result.stdout.strip()}"
    return result.stdout.strip() or "(comando executado sem saída)"
