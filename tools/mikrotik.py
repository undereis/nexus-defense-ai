"""Integração com Mikrotik RouterOS via API nativa (librouteros).

Dá à Nexus acesso de gerência completo a um roteador Mikrotik real (ex:
RB750): monitoramento, regras de firewall, usuários PPPoE, e qualquer
outra operação via run_generic_command. Diferente das outras ferramentas
ofensivas do projeto, isso é gestão de infraestrutura PRÓPRIA do
criador — não precisa de toggle de "ação ativa", mas toda escrita é
auditada e a senha nunca aparece em log.

Porta 8729 (TLS) é obrigatória para qualquer acesso fora da rede local —
a porta 8728 manda usuário/senha em texto puro.
"""

import functools
import ssl

import librouteros

from config import (
    MIKROTIK_HOST,
    MIKROTIK_PASSWORD,
    MIKROTIK_PORT,
    MIKROTIK_TIMEOUT_SECONDS,
    MIKROTIK_USE_TLS,
    MIKROTIK_USER,
)
from database.db import log_event

_ALLOWED_CHAINS = {"input", "forward", "output"}
_ALLOWED_ACTIONS = {"accept", "drop", "reject", "log", "passthrough"}

# Prefixo do comentário usado para marcar (e depois localizar) as regras de
# bloqueio de assinante inadimplente (Fase 8). O comentário é a chave de
# dedup/remoção — o roteador não tem outro identificador estável por IP.
_SUBSCRIBER_BLOCK_PREFIX = "BLOQUEIO_INADIMPLENTE_"


def _ssl_wrapper(sock):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # RouterOS usa certificado autoassinado por padrão
    return ctx.wrap_socket(sock)


def _connect():
    if not MIKROTIK_HOST or not MIKROTIK_USER:
        raise RuntimeError(
            "Mikrotik não configurado. Defina MIKROTIK_HOST, MIKROTIK_USER e "
            "MIKROTIK_PASSWORD no .env."
        )
    kwargs = {
        "host": MIKROTIK_HOST, "username": MIKROTIK_USER, "password": MIKROTIK_PASSWORD,
        "port": MIKROTIK_PORT, "timeout": MIKROTIK_TIMEOUT_SECONDS,
    }
    if MIKROTIK_USE_TLS:
        kwargs["ssl_wrapper"] = _ssl_wrapper
    return librouteros.connect(**kwargs)


def _is_configured() -> bool:
    return bool(MIKROTIK_HOST and MIKROTIK_USER)


def _safe(func):
    """Converte qualquer falha de conexão/comando (timeout, roteador
    inacessível, credencial errada) numa mensagem de erro limpa, em vez de
    deixar a exceção crua do socket/librouteros propagar e travar a
    chamada da tool no meio do agente. Antes desta correção, só
    test_connection() tinha esse tratamento — as outras 9 funções públicas
    deixavam a exceção subir sem rede de segurança."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not _is_configured():
            return "Mikrotik não configurado. Defina MIKROTIK_HOST/MIKROTIK_USER/MIKROTIK_PASSWORD no .env."
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            return (
                f"Falha ao comunicar com o Mikrotik ({MIKROTIK_HOST}:{MIKROTIK_PORT}, "
                f"timeout={MIKROTIK_TIMEOUT_SECONDS}s): {exc}"
            )
    return wrapper


@_safe
def test_connection() -> str:
    api = _connect()
    try:
        identity = list(api(cmd="/system/identity/print"))
        return f"Conexão OK com {MIKROTIK_HOST}:{MIKROTIK_PORT} — identidade: {identity[0].get('name', '?')}"
    finally:
        api.close()


@_safe
def get_system_resources() -> str:
    api = _connect()
    try:
        rows = list(api(cmd="/system/resource/print"))
    finally:
        api.close()
    if not rows:
        return "Sem dados de recursos do sistema."
    r = rows[0]
    return (
        f"CPU: {r.get('cpu-load', '?')}% | "
        f"Memória livre: {r.get('free-memory', '?')} / {r.get('total-memory', '?')} bytes | "
        f"Uptime: {r.get('uptime', '?')} | "
        f"Versão RouterOS: {r.get('version', '?')} | "
        f"Board: {r.get('board-name', '?')}"
    )


@_safe
def list_interfaces() -> str:
    api = _connect()
    try:
        rows = list(api(cmd="/interface/print"))
    finally:
        api.close()
    if not rows:
        return "Nenhuma interface encontrada."
    lines = ["Interfaces:"]
    for r in rows:
        status = "rodando" if r.get("running") else "parada"
        lines.append(f"  {r.get('name')}: {r.get('type')} — {status}")
    return "\n".join(lines)


@_safe
def list_firewall_rules(chain: str = "") -> str:
    api = _connect()
    try:
        rows = list(api(cmd="/ip/firewall/filter/print"))
    finally:
        api.close()
    if chain:
        rows = [r for r in rows if r.get("chain") == chain]
    if not rows:
        return "Nenhuma regra de firewall encontrada."
    lines = ["Regras de firewall:"]
    for r in rows:
        lines.append(
            f"  [{r.get('.id')}] chain={r.get('chain')} action={r.get('action')} "
            f"src={r.get('src-address', '*')} dst={r.get('dst-address', '*')} "
            f"proto={r.get('protocol', '*')}"
        )
    return "\n".join(lines)


@_safe
def add_firewall_rule(chain: str, action: str, src_address: str = "", dst_address: str = "", protocol: str = "", comment: str = "") -> str:
    if chain not in _ALLOWED_CHAINS:
        return f"chain inválida: {chain}. Use: {', '.join(sorted(_ALLOWED_CHAINS))}"
    if action not in _ALLOWED_ACTIONS:
        return f"action inválida: {action}. Use: {', '.join(sorted(_ALLOWED_ACTIONS))}"

    params = {"chain": chain, "action": action}
    if src_address:
        params["src-address"] = src_address
    if dst_address:
        params["dst-address"] = dst_address
    if protocol:
        params["protocol"] = protocol
    if comment:
        params["comment"] = comment

    log_event("mikrotik_firewall_add", src_address or None, f"chain={chain} action={action} params={params}", action_taken="executando")
    api = _connect()
    try:
        list(api(cmd="/ip/firewall/filter/add", **params))
    finally:
        api.close()
    log_event("mikrotik_firewall_add_confirmed", src_address or None, f"chain={chain} action={action}", action_taken="confirmado")
    return f"Regra adicionada: chain={chain} action={action}" + (f" src={src_address}" if src_address else "")


@_safe
def remove_firewall_rule(rule_id: str) -> str:
    log_event("mikrotik_firewall_remove", None, f"rule_id={rule_id}", action_taken="executando")
    api = _connect()
    try:
        list(api(cmd="/ip/firewall/filter/remove", **{".id": rule_id}))
    finally:
        api.close()
    log_event("mikrotik_firewall_remove_confirmed", None, f"rule_id={rule_id}", action_taken="confirmado")
    return f"Regra {rule_id} removida."


@_safe
def block_subscriber_ip(ip_cliente: str) -> str:
    """Bloqueio de inadimplente (Fase 8): adiciona uma regra forward/drop por
    src-address, marcada com o comentário-chave. IDEMPOTENTE — se já existe
    uma regra com esse comentário, não readiciona (evita acúmulo de regras
    duplicadas a cada ciclo de cobrança)."""
    comment = f"{_SUBSCRIBER_BLOCK_PREFIX}{ip_cliente}"
    api = _connect()
    try:
        existing = [
            r for r in api(cmd="/ip/firewall/filter/print")
            if r.get("comment") == comment
        ]
        if existing:
            return f"IP {ip_cliente} já estava bloqueado (regra existente, nada a fazer)."
        log_event("subscriber_block", ip_cliente, f"comment={comment}", action_taken="executando")
        list(api(
            cmd="/ip/firewall/filter/add",
            chain="forward", action="drop", comment=comment,
            **{"src-address": ip_cliente},
        ))
    finally:
        api.close()
    log_event("subscriber_block_confirmed", ip_cliente, f"comment={comment}", action_taken="bloqueado")
    return f"IP {ip_cliente} bloqueado (forward/drop)."


@_safe
def unblock_subscriber_ip(ip_cliente: str) -> str:
    """Desbloqueio de inadimplente (Fase 8): remove TODA regra marcada com o
    comentário-chave do IP. Idempotente — se não há regra, apenas reporta."""
    comment = f"{_SUBSCRIBER_BLOCK_PREFIX}{ip_cliente}"
    api = _connect()
    try:
        rules = [
            r for r in api(cmd="/ip/firewall/filter/print")
            if r.get("comment") == comment
        ]
        if not rules:
            return f"Nenhuma regra de bloqueio encontrada para {ip_cliente} (nada a fazer)."
        log_event("subscriber_unblock", ip_cliente, f"comment={comment} regras={len(rules)}", action_taken="executando")
        for r in rules:
            list(api(cmd="/ip/firewall/filter/remove", **{".id": r[".id"]}))
    finally:
        api.close()
    log_event("subscriber_unblock_confirmed", ip_cliente, f"comment={comment}", action_taken="desbloqueado")
    return f"IP {ip_cliente} desbloqueado ({len(rules)} regra(s) removida(s))."


@_safe
def list_pppoe_users() -> str:
    api = _connect()
    try:
        rows = list(api(cmd="/ppp/secret/print"))
    finally:
        api.close()
    if not rows:
        return "Nenhum usuário PPPoE configurado."
    lines = ["Usuários PPPoE:"]
    for r in rows:
        lines.append(f"  {r.get('name')} — perfil: {r.get('profile', 'default')} — desabilitado: {r.get('disabled', 'false')}")
    return "\n".join(lines)


@_safe
def create_pppoe_user(username: str, password: str, profile: str = "default") -> str:
    log_event("mikrotik_pppoe_create", None, f"username={username} profile={profile}", action_taken="executando")
    api = _connect()
    try:
        list(api(cmd="/ppp/secret/add", name=username, password=password, service="pppoe", profile=profile))
    finally:
        api.close()
    log_event("mikrotik_pppoe_create_confirmed", None, f"username={username}", action_taken="confirmado")
    return f"Usuário PPPoE '{username}' criado com perfil '{profile}'."


@_safe
def remove_pppoe_user(username: str) -> str:
    api = _connect()
    try:
        rows = list(api(cmd="/ppp/secret/print"))
        match = next((r for r in rows if r.get("name") == username), None)
        if not match:
            return f"Usuário PPPoE '{username}' não encontrado."
        log_event("mikrotik_pppoe_remove", None, f"username={username}", action_taken="executando")
        list(api(cmd="/ppp/secret/remove", **{".id": match[".id"]}))
    finally:
        api.close()
    log_event("mikrotik_pppoe_remove_confirmed", None, f"username={username}", action_taken="confirmado")
    return f"Usuário PPPoE '{username}' removido."


@_safe
def list_dhcp_leases() -> str:
    api = _connect()
    try:
        rows = list(api(cmd="/ip/dhcp-server/lease/print"))
    finally:
        api.close()
    if not rows:
        return "Nenhum lease DHCP ativo."
    lines = ["Leases DHCP:"]
    for r in rows:
        lines.append(f"  {r.get('address')} -> {r.get('mac-address')} ({r.get('host-name', 'sem hostname')})")
    return "\n".join(lines)


@_safe
def run_generic_command(path: str, params: dict | None = None) -> str:
    """Roda qualquer comando RouterOS no formato de menu (ex:
    '/ip/address/print', '/interface/wireless/print'). Fallback para
    operações que não têm uma função dedicada. Toda chamada é auditada."""
    params = params or {}
    log_event("mikrotik_generic_command", None, f"path={path} params={params}", action_taken="executando")
    api = _connect()
    try:
        rows = list(api(cmd=path, **params))
    finally:
        api.close()
    log_event("mikrotik_generic_command_confirmed", None, f"path={path}", action_taken="concluido")
    if not rows:
        return "Comando executado, sem retorno de dados."
    return "\n".join(str(r) for r in rows[:50])
