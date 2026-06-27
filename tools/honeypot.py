"""Honeypot multi-serviço: detecção ativa por armadilha.

Diferente de tudo que a Nexus tinha antes (que detecta por VOLUME de
tráfego — pode ter falso positivo), o honeypot é uma porta que não
serve nenhum propósito real: ninguém deveria conectar nela. Qualquer
conexão é, por definição, alguém varrendo a rede.

Suporta 3 perfis de serviço simultâneos:
- ssh: só banner falso (protocolo SSH real é criptografado, não dá pra
  simular um login sem implementar o handshake completo).
- ftp: protocolo texto simples — captura USER/PASS reais que o
  atacante digitar, sempre nega o login (530), mas a credencial já foi
  capturada.
- http: serve uma página de login HTTP falsa; captura usuário/senha de
  qualquer POST recebido, sempre responde com erro de credencial.

O isolamento do IP é imediato e automático (nunca para loopback) — não
depende de ALLOW_ACTIVE_EXPLOITATION, porque bloquear IP sempre foi
capacidade "core" da Nexus.
"""

import ipaddress
import re
import socket
import threading
from urllib.parse import parse_qs

from config import HONEYPOT_BANNER, HONEYPOT_PORT
from database.db import (
    count_honeypot_hits,
    list_honeypot_credentials,
    list_honeypot_hits,
    log_event,
    record_honeypot_credential,
    record_honeypot_hit,
)
from tools import firewall, notify
from tools.threat_intel import record_confirmed_isolation

SUPPORTED_SERVICES = {"ssh", "ftp", "http"}

_lock = threading.Lock()
_listeners: dict[tuple[str, int], dict] = {}  # (service, port) -> {thread, stop_event, socket}

# (service, port) que o criador parou manualmente via stop(). O watchdog
# (tools/watchdog.py) respeita isso e NÃO reergue esses serviços — sem
# isso, ele lia só HONEYPOT_SERVICES do .env e ressuscitava qualquer
# honeypot pausado manualmente no ciclo seguinte (até 60s depois), o que
# também gerava uma notificação repetida no terminal a cada ciclo.
_manually_stopped: set[tuple[str, int]] = set()


def _is_safe_to_isolate(ip: str) -> bool:
    """Nunca isola loopback (127.0.0.0/8, ::1) — testar o próprio honeypot
    da própria máquina não deve travar o acesso local a ela mesma."""
    try:
        return not ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def _isolate(ip: str, port: int, service: str):
    if not _is_safe_to_isolate(ip):
        log_event(
            "honeypot_isolation_skipped", ip, "IP de loopback — nunca isolado", action_taken="ignorado"
        )
        return
    reason = f"Honeypot ({service}): conectou na porta-armadilha {port} (evidência direta de varredura)"
    result = firewall.block_ip(ip, reason)
    record_confirmed_isolation(ip, reason)
    notify.send_notification(
        "Nexus: honeypot capturou um atacante",
        f"IP {ip} conectou no honeypot {service} na porta {port}.\n{result}",
    )


def _process_hit(ip: str, port: int, service: str):
    record_honeypot_hit(ip, port, service)
    total_hits = count_honeypot_hits(ip)
    log_event(
        "honeypot_hit", ip, f"service={service} port={port} total_hits={total_hits}",
        action_taken="detectado",
    )
    _isolate(ip, port, service)


def _process_credential(ip: str, port: int, service: str, username: str | None, password: str | None):
    record_honeypot_credential(ip, port, service, username, password)
    log_event(
        "honeypot_credential_captured", ip,
        f"service={service} port={port} username={username!r}",
        action_taken="capturado",
    )
    notify.send_notification(
        "Nexus: credencial capturada pelo honeypot",
        f"IP {ip} tentou login no honeypot {service} (porta {port})\n"
        f"usuário={username!r} senha={password!r}",
    )


def _handle_ssh(conn: socket.socket, ip: str, port: int):
    try:
        if HONEYPOT_BANNER:
            conn.sendall(HONEYPOT_BANNER.encode())
    except OSError:
        pass
    finally:
        conn.close()


_FTP_USER_RE = re.compile(rb"^USER\s+(.*)$", re.IGNORECASE)
_FTP_PASS_RE = re.compile(rb"^PASS\s+(.*)$", re.IGNORECASE)


def _handle_ftp(conn: socket.socket, ip: str, port: int):
    """Processa linhas por buffer acumulado, não por recv() — alguns
    clientes/scanners mandam USER e PASS no mesmo pacote TCP sem esperar
    a resposta intermediária do servidor, então um recv() por linha
    perderia o PASS."""
    username = None
    password = None
    buffer = b""
    try:
        conn.sendall(b"220 ProFTPD 1.3.5 Server ready.\r\n")
        conn.settimeout(10)

        while password is None:
            chunk = conn.recv(256)
            if not chunk:
                break
            buffer += chunk

            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                line = line.strip(b"\r")

                if username is None:
                    match = _FTP_USER_RE.match(line)
                    if match:
                        username = match.group(1).decode(errors="replace")
                        conn.sendall(b"331 Password required.\r\n")
                        continue

                if username is not None and password is None:
                    match = _FTP_PASS_RE.match(line)
                    if match:
                        password = match.group(1).decode(errors="replace")

        if username or password:
            _process_credential(ip, port, "ftp", username, password)

        conn.sendall(b"530 Login incorrect.\r\n")
    except (OSError, socket.timeout):
        pass
    finally:
        conn.close()


_LOGIN_PAGE = b"""HTTP/1.1 200 OK\r
Content-Type: text/html\r
Connection: close\r
\r
<html><body><h2>Admin Login</h2>
<form method="POST"><input name="username" placeholder="user">
<input name="password" type="password" placeholder="pass">
<button>Login</button></form></body></html>"""

_LOGIN_FAILED = b"""HTTP/1.1 401 Unauthorized\r
Content-Type: text/html\r
Connection: close\r
\r
<html><body><h3>Invalid credentials.</h3></body></html>"""


def _handle_http(conn: socket.socket, ip: str, port: int):
    try:
        conn.settimeout(10)
        request = b""
        conn_data = conn.recv(4096)
        request += conn_data

        if request.startswith(b"POST"):
            body = request.split(b"\r\n\r\n", 1)[-1]
            fields = parse_qs(body.decode(errors="replace"))
            username = (fields.get("username") or [None])[0]
            password = (fields.get("password") or [None])[0]
            if username or password:
                _process_credential(ip, port, "http", username, password)
            conn.sendall(_LOGIN_FAILED)
        else:
            conn.sendall(_LOGIN_PAGE)
    except (OSError, socket.timeout):
        pass
    finally:
        conn.close()


_HANDLERS = {"ssh": _handle_ssh, "ftp": _handle_ftp, "http": _handle_http}


def _handle_connection(conn: socket.socket, addr: tuple, port: int, service: str):
    ip = addr[0]  # addr[1] é a porta de ORIGEM do cliente, não a do honeypot
    try:
        _HANDLERS[service](conn, ip, port)
    finally:
        try:
            _process_hit(ip, port, service)
        except Exception as exc:
            log_event("honeypot_error", ip, str(exc))


def _listen_loop(service: str, port: int, stop_event: threading.Event, ready: threading.Event, bind_error: list):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", port))
    except OSError as exc:
        log_event("honeypot_error", None, f"Falha ao abrir porta {port} ({service}): {exc}")
        bind_error.append(str(exc))
        ready.set()
        return
    server.listen(20)
    server.settimeout(1.0)
    with _lock:
        if (service, port) in _listeners:
            _listeners[(service, port)]["socket"] = server
    ready.set()

    try:
        while not stop_event.is_set():
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=_handle_connection, args=(conn, addr, port, service), daemon=True
            ).start()
    finally:
        server.close()


def start(service: str = "ssh", port: int = 0) -> str:
    """Inicia um honeypot de um serviço numa porta. Idempotente por
    (service, port): se já estiver rodando essa combinação, avisa.

    Espera a confirmação real do bind antes de reportar sucesso — antes
    desta correção, start() sempre retornava a mensagem otimista mesmo
    quando o bind falhava (porta já em uso por outro processo, por
    exemplo), e quem chamava (inclusive o watchdog) não tinha como saber
    que na verdade nada subiu. Isso causava um loop silencioso: o
    watchdog via a thread morta, chamava start() de novo, falhava de
    novo do mesmo jeito, e reportava 'reergueu' a cada ciclo sem nunca
    corrigir nada de fato."""
    if service not in SUPPORTED_SERVICES:
        return f"Serviço não suportado: {service}. Opções: {', '.join(sorted(SUPPORTED_SERVICES))}"
    port = port or HONEYPOT_PORT
    key = (service, port)
    with _lock:
        existing = _listeners.get(key)
        if existing and existing["thread"].is_alive():
            _manually_stopped.discard(key)
            return f"Honeypot {service} já está rodando na porta {port}."
        stop_event = threading.Event()
        ready = threading.Event()
        bind_error: list = []
        thread = threading.Thread(
            target=_listen_loop, args=(service, port, stop_event, ready, bind_error), daemon=True
        )
        _listeners[key] = {"thread": thread, "stop_event": stop_event, "socket": None}
        thread.start()

    ready.wait(timeout=3)
    if bind_error:
        with _lock:
            _listeners.pop(key, None)
        return (
            f"Falha ao iniciar honeypot {service} na porta {port}: {bind_error[0]}. "
            "Provavelmente outro processo já está usando essa porta — verifique com "
            f"'lsof -i :{port}' antes de tentar de novo."
        )
    if not ready.is_set():
        with _lock:
            _listeners.pop(key, None)
        return f"Honeypot {service} na porta {port} não respondeu em 3s — não foi possível confirmar se subiu."

    with _lock:
        _manually_stopped.discard(key)
    return f"Honeypot {service} iniciado na porta {port}. Qualquer conexão será tratada como ataque confirmado."


def stop(service: str | None = None, port: int | None = None) -> str:
    """Para um honeypot específico (service+port), ou todos se nenhum for informado."""
    with _lock:
        keys = list(_listeners.keys())
        if service is not None or port is not None:
            keys = [k for k in keys if (service is None or k[0] == service) and (port is None or k[1] == port)]

        if not keys:
            return "Nenhum honeypot rodando com esses critérios."

        stopped = []
        for key in keys:
            entry = _listeners.get(key)
            if entry and entry["thread"].is_alive():
                entry["stop_event"].set()
                entry["thread"].join(timeout=3)
                stopped.append(f"{key[0]}:{key[1]}")
            _listeners.pop(key, None)
            _manually_stopped.add(key)

    return f"Honeypot(s) parado(s): {', '.join(stopped)}" if stopped else "Nenhum honeypot ativo para parar."


def is_manually_stopped(service: str, port: int) -> bool:
    """Usado pelo watchdog para não reerguer um honeypot que o criador
    pausou de propósito via stop()."""
    return (service, port) in _manually_stopped


def is_running(service: str | None = None) -> bool:
    with _lock:
        for (svc, _port), entry in _listeners.items():
            if (service is None or svc == service) and entry["thread"].is_alive():
                return True
    return False


def list_running() -> list[tuple[str, int]]:
    with _lock:
        return [key for key, entry in _listeners.items() if entry["thread"].is_alive()]


def describe_hits(limit: int = 20) -> str:
    rows = list_honeypot_hits(limit)
    running = list_running()
    running_desc = ", ".join(f"{s}:{p}" for s, p in running) if running else "nenhum"
    if not rows:
        return f"Nenhuma conexão capturada pelo honeypot ainda. Rodando agora: {running_desc}."
    lines = [f"Capturas do honeypot (mais recente primeiro). Rodando agora: {running_desc}:"]
    for ip, port, service, timestamp in rows:
        lines.append(f"  [{timestamp}] {ip} -> {service}:{port}")
    return "\n".join(lines)


def describe_credentials(limit: int = 50) -> str:
    rows = list_honeypot_credentials(limit)
    if not rows:
        return "Nenhuma credencial capturada ainda."
    lines = ["Credenciais capturadas pelo honeypot (mais recente primeiro):"]
    for ip, port, service, username, password, timestamp in rows:
        lines.append(f"  [{timestamp}] {ip} ({service}:{port}) -> usuário={username!r} senha={password!r}")
    return "\n".join(lines)
