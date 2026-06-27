"""Honeytokens em sistemas reais: arquivos-isca com callback (canary
token) e credenciais-isca plantadas em infraestrutura real (Mikrotik).

Diferente do honeypot (porta de rede que não deveria existir), o
honeytoken é um ARTEFATO plantado dentro de sistemas reais — um arquivo
que parece ter credenciais de verdade, um usuário PPPoE que não devia
existir. Qualquer acesso é, por definição, comprometimento confirmado,
e detecta ameaça INTERNA também (alguém com acesso legítimo à máquina
abrindo um arquivo que não devia abrir), não só ataque externo.

Mecanismo do arquivo-isca: o arquivo contém uma URL única embutida (o
"canary token", técnica clássica popularizada pelo canarytokens.org).
Quando alguém abre o arquivo — em qualquer lugar do mundo, mesmo que
tenha sido exfiltrado — e o link "telefona pra casa", a Nexus recebe a
notificação. Isso exige CANARY_BASE_URL configurado (endereço público
alcançável de fora) — sem isso, o arquivo é só um arquivo, sem callback
real, e a tool avisa isso explicitamente em vez de fingir que funciona.

Credencial-isca: hoje só está integrada ao Mikrotik (único sistema
externo real que a Nexus já gerencia) — um usuário PPPoE plantado que
nenhum cliente de verdade deveria usar. Detecção via sessões ativas
reais do RouterOS (/ppp/active/print), não inferência.
"""

import re
import secrets
import socket
import threading

from database.db import (
    get_honeytoken_triggers,
    list_honeytokens,
    log_event,
    plant_honeytoken,
    record_honeytoken_trigger,
)
from tools import firewall, notify
from tools.threat_intel import record_confirmed_isolation

from config import CANARY_BASE_URL, CANARY_LISTENER_PORT

# Socket bruto com loop de accept (não http.server/socketserver) — mesmo
# padrão já usado e validado em tools/honeypot.py para os 7 serviços.
# socketserver.ThreadingHTTPServer (baseado em select/poll internos) não
# aceitava conexões de forma confiável neste ambiente sandboxed, mesmo
# com bind/listen confirmados — o loop manual de accept() funciona.
_CANARY_PATH_RE = re.compile(rb"^GET\s+/canary/([0-9a-f]+)")
_USER_AGENT_RE = re.compile(rb"User-Agent:\s*(.*?)\r\n", re.IGNORECASE)

_canary_socket: socket.socket | None = None
_canary_thread: socket.socket | None = None
_canary_stop_event: threading.Event | None = None
_canary_lock = threading.Lock()


def _handle_canary_connection(conn: socket.socket, ip: str):
    try:
        conn.settimeout(5)
        request = conn.recv(4096)
        match = _CANARY_PATH_RE.match(request)
        if match:
            token_id = match.group(1).decode()
            ua_match = _USER_AGENT_RE.search(request)
            user_agent = ua_match.group(1).decode(errors="replace") if ua_match else ""
            handle_canary_trigger(token_id, ip, user_agent)
        conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nNot Found")
    except (OSError, socket.timeout):
        pass
    finally:
        conn.close()


def _canary_listen_loop(server: socket.socket, stop_event: threading.Event):
    server.settimeout(1.0)
    try:
        while not stop_event.is_set():
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=_handle_canary_connection, args=(conn, addr[0]), daemon=True).start()
    finally:
        server.close()


def start_canary_listener(port: int | None = None) -> str:
    """Inicia o listener HTTP que recebe os callbacks dos arquivos-isca.
    Sem isso rodando, plant_decoy_file ainda funciona, mas nenhum
    callback real chega — o arquivo fica "mudo"."""
    global _canary_socket, _canary_thread, _canary_stop_event

    port = port or CANARY_LISTENER_PORT
    with _canary_lock:
        if _canary_socket is not None:
            return f"Listener de canário já está rodando na porta {port}."
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("0.0.0.0", port))
        except OSError as exc:
            return f"Falha ao iniciar listener de canário na porta {port}: {exc}"
        server.listen(20)
        _canary_socket = server
        _canary_stop_event = threading.Event()
        _canary_thread = threading.Thread(
            target=_canary_listen_loop, args=(server, _canary_stop_event), daemon=True
        )
        _canary_thread.start()
    return f"Listener de canário rodando na porta {port}."


def stop_canary_listener() -> str:
    global _canary_socket, _canary_thread, _canary_stop_event
    with _canary_lock:
        if _canary_socket is None:
            return "Listener de canário não está rodando."
        _canary_stop_event.set()
        _canary_thread.join(timeout=3)
        _canary_socket = None
        _canary_thread = None
        _canary_stop_event = None
    return "Listener de canário parado."


def is_canary_listener_running() -> bool:
    return _canary_socket is not None

_DECOY_TEMPLATES = {
    "aws_credentials": (
        "aws_credentials_backup.txt",
        "[default]\naws_access_key_id = AKIA{rand}\n"
        "aws_secret_access_key = {secret}\n"
        "# Backup de credenciais — não compartilhar.\n"
        "# Verificação de integridade: {url}\n",
    ),
    "ssh_key": (
        "id_rsa_backup",
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB{rand}\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
        "# Restaurar de: {url}\n",
    ),
    "database_backup": (
        "db_backup_credentials.txt",
        "host=db-prod.internal\nuser=admin\npassword={secret}\n"
        "# Status do backup: {url}\n",
    ),
}


def _generate_token_id() -> str:
    return secrets.token_hex(8)


def plant_decoy_file(kind: str, directory) -> str:
    """Cria um arquivo-isca convincente (kind: aws_credentials, ssh_key,
    ou database_backup) dentro de `directory`, com uma URL de callback
    única embutida. Qualquer requisição a essa URL é comprometimento
    confirmado. Exige CANARY_BASE_URL configurado no .env."""
    if kind not in _DECOY_TEMPLATES:
        return f"Tipo de isca desconhecido: {kind!r}. Opções: {', '.join(_DECOY_TEMPLATES)}."
    if not CANARY_BASE_URL:
        return (
            "CANARY_BASE_URL não configurado no .env — sem um endereço público "
            "alcançável de fora, o arquivo-isca não teria como avisar a Nexus se "
            "alguém abrir. Configure isso antes de plantar arquivos de verdade."
        )

    from pathlib import Path
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)

    token_id = _generate_token_id()
    filename, template = _DECOY_TEMPLATES[kind]
    callback_url = f"{CANARY_BASE_URL.rstrip('/')}/canary/{token_id}"
    content = template.format(
        rand=secrets.token_hex(8), secret=secrets.token_urlsafe(24), url=callback_url
    )

    file_path = directory / filename
    file_path.write_text(content)
    plant_honeytoken(token_id, kind, str(file_path))

    return (
        f"Arquivo-isca '{kind}' plantado em {file_path}. Token {token_id}. "
        f"Qualquer acesso à URL embutida ({callback_url}) será tratado como "
        "comprometimento confirmado. Lembre-se de iniciar o listener de canário "
        "(start_canary_listener) para de fato receber o callback."
    )


def handle_canary_trigger(token_id: str, source_ip: str | None, user_agent: str | None) -> bool:
    """Chamado pelo listener HTTP quando uma URL de canário é acessada.
    Retorna True se era um token real (e já dispara isolamento), False
    se token_id não existe (alguém adivinhando URLs aleatórias, não
    conta como honeytoken disparado)."""
    triggered = record_honeytoken_trigger(token_id, source_ip, user_agent)
    if not triggered:
        return False

    log_event(
        "honeytoken_triggered", source_ip,
        f"token={token_id} user_agent={user_agent!r}", action_taken="comprometimento confirmado",
    )
    notify.send_notification(
        "Nexus: HONEYTOKEN DISPARADO — comprometimento confirmado",
        f"Token {token_id} foi acessado por {source_ip or 'IP desconhecido'}.\n"
        "Isso significa que um arquivo-isca foi aberto — ameaça interna OU "
        "exfiltração de dados confirmada, não é falso positivo possível.",
    )
    # Nunca isola loopback — mesmo cuidado do honeypot (tools/honeypot.py
    # _is_safe_to_isolate): testar o próprio canário da própria máquina
    # não deve travar o acesso local a ela mesma. Achado testando de
    # verdade contra um listener real, não hipotético.
    if source_ip and not _is_loopback(source_ip):
        result = firewall.block_ip(source_ip, f"Honeytoken {token_id} disparado")
        record_confirmed_isolation(source_ip, f"Honeytoken {token_id} disparado")
        log_event("honeytoken_isolation", source_ip, result, action_taken="isolado")
    return True


def _is_loopback(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def describe_honeytokens() -> str:
    rows = list_honeytokens()
    if not rows:
        return "Nenhum honeytoken plantado ainda."
    lines = ["Honeytokens plantados:"]
    for token_id, kind, location, planted_at, triggered_count, last_triggered_at in rows:
        status = (
            f"DISPARADO {triggered_count}x, último em {last_triggered_at}"
            if triggered_count else "nunca disparado"
        )
        lines.append(f"  [{token_id}] {kind} em {location} (plantado {planted_at}) — {status}")
    return "\n".join(lines)


def describe_token_triggers(token_id: str) -> str:
    rows = get_honeytoken_triggers(token_id)
    if not rows:
        return f"Token {token_id} nunca foi disparado (ou não existe)."
    lines = [f"Disparos do token {token_id}:"]
    for source_ip, user_agent, timestamp in rows:
        lines.append(f"  [{timestamp}] IP={source_ip} user_agent={user_agent!r}")
    return "\n".join(lines)


# --- Credencial-isca no Mikrotik ---
#
# Hoje só integrado ao Mikrotik porque é o único sistema externo real
# que a Nexus já gerencia (via API nativa RouterOS). "Painéis" genéricos
# (ex: sistema de billing/gestão da Xfiber) não estão integrados — se o
# criador tiver um sistema específico em mente, isso precisa ser
# definido e construído à parte; não dá pra fingir integração com um
# sistema que a Nexus não conhece.
#
# A credencial-isca em si (criar o usuário PPPoE) passa pelo MESMO gate
# de risco que qualquer outra escrita no Mikrotik (mikrotik_create_
# pppoe_user já é gated em tools/risk.py) — plantar uma isca ainda é
# uma escrita real num roteador de produção, merece a mesma cautela.

_DECOY_USERNAME_PREFIX = "isca-seguranca-"


def generate_decoy_pppoe_username() -> str:
    """Gera um nome de usuário PPPoE-isca improvável de colidir com um
    cliente real, e fácil de reconhecer como honeytoken depois."""
    return f"{_DECOY_USERNAME_PREFIX}{secrets.token_hex(4)}"


def register_pppoe_honeytoken(username: str) -> str:
    """Registra (na tabela de honeytokens) que um usuário PPPoE é uma
    isca — chame isso DEPOIS de confirmar a criação real via
    mikrotik_create_pppoe_user (que já passa pelo gate de risco).
    Sem isso, check_pppoe_honeytoken_logins não saberia quais usuários
    são iscas."""
    plant_honeytoken(username, "pppoe_credential", f"Mikrotik PPPoE: {username}")
    if not username.startswith(_DECOY_USERNAME_PREFIX):
        return (
            f"Aviso: '{username}' não usa o prefixo {_DECOY_USERNAME_PREFIX!r} — "
            "ainda registrado como honeytoken, mas considere usar "
            "generate_decoy_pppoe_username() para evitar confusão com clientes reais."
        )
    return f"Usuário PPPoE '{username}' registrado como honeytoken."


def check_pppoe_honeytoken_logins() -> str:
    """Verifica, nas sessões PPPoE ATIVAS reais do Mikrotik agora, se
    algum usuário-isca está conectado — login com credencial-isca é
    comprometimento confirmado (alguém usou uma credencial que nenhum
    cliente real deveria ter). Detecção via dado real do RouterOS
    (/ppp/active/print), não inferência."""
    from tools import mikrotik

    active_raw = mikrotik.run_generic_command("/ppp/active/print")
    if "Falha ao comunicar" in active_raw or "não configurado" in active_raw:
        return f"Não foi possível consultar sessões PPPoE ativas no Mikrotik: {active_raw}"

    decoy_tokens = [t for t in list_honeytokens() if t[1] == "pppoe_credential"]
    if not decoy_tokens:
        return "Nenhuma credencial-isca PPPoE registrada ainda."

    triggered = []
    for token_id, _kind, _location, _planted_at, _count, _last in decoy_tokens:
        if token_id in active_raw:
            triggered.append(token_id)
            handle_canary_trigger(token_id, None, "mikrotik-pppoe-session")

    if not triggered:
        return f"Nenhuma das {len(decoy_tokens)} credencial(is)-isca PPPoE está conectada agora."
    return (
        f"COMPROMETIMENTO CONFIRMADO: {len(triggered)} credencial(is)-isca PPPoE "
        f"conectada(s) agora: {', '.join(triggered)}."
    )
