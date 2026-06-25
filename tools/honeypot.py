"""Honeypot: detecção ativa por armadilha.

Diferente de tudo que a Nexus tinha até aqui (que detecta por VOLUME de
tráfego — pode ter falso positivo), o honeypot é uma porta que não
serve nenhum propósito real: ninguém deveria conectar nela. Qualquer
conexão é, por definição, alguém varrendo a rede — não precisa de
threshold, não precisa de julgamento, é evidência direta. Por isso o
isolamento aqui é imediato e automático, sem depender de
ALLOW_ACTIVE_EXPLOITATION (bloquear IP já é uma capacidade "core" da
Nexus, como isolate_ip sempre foi).
"""

import ipaddress
import socket
import threading

from config import HONEYPOT_BANNER, HONEYPOT_PORT
from database.db import count_honeypot_hits, list_honeypot_hits, log_event, record_honeypot_hit
from tools import firewall, notify
from tools.threat_intel import record_threat_isolation

_lock = threading.Lock()
_server_socket: socket.socket | None = None
_listener_thread: threading.Thread | None = None
_stop_event = threading.Event()


def _is_safe_to_isolate(ip: str) -> bool:
    """Nunca isola loopback (127.0.0.0/8, ::1) — testar o próprio honeypot
    da própria máquina não deve travar o acesso local a ela mesma."""
    try:
        return not ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def _process_hit(ip: str, port: int):
    record_honeypot_hit(ip, port)
    total_hits = count_honeypot_hits(ip)
    log_event(
        "honeypot_hit", ip, f"port={port} total_hits={total_hits}", action_taken="detectado"
    )

    if not _is_safe_to_isolate(ip):
        log_event(
            "honeypot_isolation_skipped", ip, "IP de loopback — nunca isolado", action_taken="ignorado"
        )
        return

    reason = f"Honeypot: conectou na porta-armadilha {port} (evidência direta de varredura)"
    result = firewall.block_ip(ip, reason)
    record_threat_isolation(ip)

    notify.send_notification(
        "Nexus: honeypot capturou um atacante",
        f"IP {ip} conectou na porta-armadilha {port}.\n{result}",
    )


def _handle_connection(conn: socket.socket, addr: tuple, listen_port: int):
    ip = addr[0]  # addr[1] é a porta de ORIGEM do cliente, não a do honeypot
    try:
        if HONEYPOT_BANNER:
            conn.sendall(HONEYPOT_BANNER.encode())
    except OSError:
        pass
    finally:
        conn.close()
    try:
        _process_hit(ip, listen_port)
    except Exception as exc:
        log_event("honeypot_error", ip, str(exc))


def _listen_loop(port: int):
    global _server_socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", port))
    except OSError as exc:
        log_event("honeypot_error", None, f"Falha ao abrir porta {port}: {exc}")
        return
    server.listen(20)
    server.settimeout(1.0)
    _server_socket = server

    try:
        while not _stop_event.is_set():
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=_handle_connection, args=(conn, addr, port), daemon=True
            ).start()
    finally:
        server.close()
        _server_socket = None


def start(port: int = HONEYPOT_PORT) -> str:
    """Inicia o honeypot numa porta. Idempotente: se já estiver rodando,
    avisa em vez de abrir duas vezes."""
    global _listener_thread
    with _lock:
        if _listener_thread and _listener_thread.is_alive():
            return f"Honeypot já está rodando na porta {port}."
        _stop_event.clear()
        _listener_thread = threading.Thread(target=_listen_loop, args=(port,), daemon=True)
        _listener_thread.start()
    return f"Honeypot iniciado na porta {port}. Qualquer conexão será tratada como ataque confirmado."


def stop() -> str:
    global _listener_thread
    with _lock:
        if not _listener_thread or not _listener_thread.is_alive():
            return "Honeypot não está rodando."
        _stop_event.set()
        _listener_thread.join(timeout=3)
        _listener_thread = None
    return "Honeypot parado."


def is_running() -> bool:
    return bool(_listener_thread and _listener_thread.is_alive())


def describe_hits(limit: int = 20) -> str:
    rows = list_honeypot_hits(limit)
    if not rows:
        return "Nenhuma conexão capturada pelo honeypot ainda."
    lines = [f"Capturas do honeypot (mais recente primeiro), rodando: {is_running()}:"]
    for ip, port, timestamp in rows:
        lines.append(f"  [{timestamp}] {ip} -> porta {port}")
    return "\n".join(lines)
