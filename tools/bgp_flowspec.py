"""BGP FlowSpec (RFC 5575): anunciar regras de filtragem de tráfego via
BGP para o upstream bloquear DDoS antes de chegar na borda da Xfiber.

Diferente de isolate_ip (que bloqueia LOCALMENTE, depois que o tráfego
já chegou), FlowSpec pede para o roteador do PROVEDOR UPSTREAM descartar
o tráfego antes mesmo de atravessar o link de trânsito — é o que de
fato protege contra DDoS volumétrico grande, porque o link da Xfiber
nunca fica saturado.

Mecanismo real: o BGP speaker que conversa com o upstream (tipicamente
ExaBGP, não o Mikrotik — RouterOS não tem suporte nativo robusto a
FlowSpec sender) recebe comandos no formato `announce flow route { ... }`
através de um pipe/API. Este módulo só constrói e valida a regra, e
manda o comando para esse pipe SE ele estiver configurado
(EXABGP_API_PIPE) — sem isso, fica em modo "só validação", honesto
sobre não ter para onde mandar o anúncio ainda.

BARREIRA DE SEGURANÇA CRÍTICA: anunciar ou retirar uma regra FlowSpec
NUNCA executa direto — sempre passa pelo gate de confirmação de
tools/risk.py (mesmo código fora de banda usado para Mikrotik/exploração
ativa). Isso programa o roteamento de uma rede de produção real (Xfiber)
com clientes reais — um erro aqui pode causar apagão de tráfego legítimo,
não só bloquear o atacante. Diferente das outras tools gated, aqui
isso não é opcional nem discutível.

NUNCA VALIDADO CONTRA UMA SESSÃO BGP REAL — ExaBGP não está instalado,
e não há sessão de trânsito configurada neste ambiente. A construção e
validação da regra está testada e correta (RFC 5575), mas o envio de
verdade para um upstream real nunca foi confirmado. Antes de usar isso
em produção, valide manualmente contra um laboratório (ex: ExaBGP +
BIRD/FRR simulando o upstream) — NUNCA contra a sessão de produção
sem esse passo antes.
"""

import ipaddress
import re
import shutil
import subprocess

from config import EXABGP_API_PIPE
from database.db import (
    get_flowspec_rule,
    list_active_flowspec_rules,
    log_event,
    mark_flowspec_rule_withdrawn,
    record_flowspec_rule,
)

VALID_PROTOCOLS = {"tcp", "udp", "icmp"}
VALID_ACTIONS = {"discard", "accept", "rate-limit"}
_PORT_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")


def _validate_prefix(prefix: str) -> str:
    try:
        return str(ipaddress.ip_network(prefix, strict=False))
    except ValueError as exc:
        raise ValueError(f"Prefixo IP inválido: {prefix!r} ({exc})")


def _validate_port(port: str) -> str:
    port = port.strip()
    if not port:
        return ""
    if not _PORT_RE.match(port):
        raise ValueError(f"Porta(s) inválida(s): {port!r}. Use '80', '80,443' ou '1024-2048'.")
    return port


def build_rule(
    dest_prefix: str,
    protocol: str = "",
    dest_port: str = "",
    source_prefix: str = "",
    action: str = "discard",
    rate_limit_bps: int | None = None,
) -> dict:
    """Constrói e valida uma regra FlowSpec (RFC 5575), sem anunciar nada
    ainda. Lança ValueError se algum campo for inválido — chame isto
    antes de propor o anúncio, para validar e mostrar a regra ao criador
    antes mesmo de criar a ação pendente."""
    dest_prefix = _validate_prefix(dest_prefix)
    source_prefix = _validate_prefix(source_prefix) if source_prefix else ""
    dest_port = _validate_port(dest_port)
    protocol = protocol.strip().lower()
    if protocol and protocol not in VALID_PROTOCOLS:
        raise ValueError(f"Protocolo inválido: {protocol!r}. Use: {', '.join(sorted(VALID_PROTOCOLS))}.")
    action = action.strip().lower()
    if action not in VALID_ACTIONS:
        raise ValueError(f"Action inválida: {action!r}. Use: {', '.join(sorted(VALID_ACTIONS))}.")
    if action == "rate-limit" and not rate_limit_bps:
        raise ValueError("action='rate-limit' exige rate_limit_bps (ex: 1000000 para 1 Mbps).")

    match_parts = [f"destination {dest_prefix};"]
    if source_prefix:
        match_parts.append(f"source {source_prefix};")
    if protocol:
        match_parts.append(f"protocol {protocol};")
    if dest_port:
        match_parts.append(f"destination-port {dest_port};")

    if action == "discard":
        then_part = "discard;"
    elif action == "accept":
        then_part = "accept;"
    else:
        then_part = f"rate-limit {rate_limit_bps};"

    rule_text = (
        "flow {\n  route {\n    match {\n      "
        + "\n      ".join(match_parts)
        + "\n    }\n    then {\n      "
        + then_part
        + "\n    }\n  }\n}"
    )

    description = (
        f"destino={dest_prefix}"
        + (f" origem={source_prefix}" if source_prefix else "")
        + (f" protocolo={protocol}" if protocol else "")
        + (f" porta={dest_port}" if dest_port else "")
        + f" ação={action}"
        + (f"({rate_limit_bps} bps)" if action == "rate-limit" else "")
    )

    return {"rule_text": rule_text, "description": description}


def _send_to_exabgp(command: str) -> str:
    """Manda um comando ('announce flow route ...' ou 'withdraw flow
    route ...') para o pipe de controle do ExaBGP. Sem EXABGP_API_PIPE
    configurado, retorna aviso claro em vez de fingir que enviou."""
    if not EXABGP_API_PIPE:
        return (
            "EXABGP_API_PIPE não configurado no .env — a regra foi validada e "
            "registrada, mas NÃO foi enviada a nenhum BGP speaker real (não há "
            "sessão de trânsito configurada ainda)."
        )
    if shutil.which("exabgpcli"):
        result = subprocess.run(["exabgpcli", command], capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            return f"Falha ao enviar comando ao ExaBGP via exabgpcli: {result.stderr.strip()}"
        return f"Comando enviado ao ExaBGP via exabgpcli: {result.stdout.strip() or 'ok'}"
    try:
        with open(EXABGP_API_PIPE, "w") as pipe:
            pipe.write(command + "\n")
        return f"Comando escrito no pipe do ExaBGP ({EXABGP_API_PIPE})."
    except OSError as exc:
        return f"Falha ao escrever no pipe do ExaBGP ({EXABGP_API_PIPE}): {exc}"


def announce_flowspec_rule(
    dest_prefix: str, protocol: str = "", dest_port: str = "",
    source_prefix: str = "", action: str = "discard", rate_limit_bps: int | None = None,
) -> str:
    """Constrói a regra de novo (a partir dos argumentos guardados na ação
    pendente) e envia o anúncio de verdade. SÓ é chamada pelo gate de
    confirmação (tools/risk.py) depois de aprovação explícita — nunca
    direto."""
    rule = build_rule(dest_prefix, protocol, dest_port, source_prefix, action, rate_limit_bps)
    rule_id = record_flowspec_rule(rule["rule_text"], rule["description"])
    log_event(
        "bgp_flowspec_announced", dest_prefix, f"id={rule_id} {rule['description']}", action_taken="anunciado"
    )
    send_result = _send_to_exabgp(f"announce flow route {rule['rule_text']}")
    return f"Regra FlowSpec #{rule_id} ({rule['description']}) registrada.\n{send_result}"


def withdraw_flowspec_rule(rule_id: int) -> str:
    """Retira uma regra FlowSpec já anunciada. SÓ é chamada pelo gate de
    confirmação, igual ao anúncio."""
    row = get_flowspec_rule(rule_id)
    if row is None:
        return f"Regra FlowSpec #{rule_id} não encontrada."
    _id, rule_text, description, status, _created_at, _withdrawn_at = row
    if status != "announced":
        return f"Regra FlowSpec #{rule_id} já está com status '{status}'."

    send_result = _send_to_exabgp(f"withdraw flow route {rule_text}")
    mark_flowspec_rule_withdrawn(rule_id)
    log_event("bgp_flowspec_withdrawn", None, f"id={rule_id} {description}", action_taken="retirado")
    return f"Regra FlowSpec #{rule_id} ({description}) retirada.\n{send_result}"


def list_active_rules() -> str:
    rows = list_active_flowspec_rules()
    if not rows:
        return "Nenhuma regra FlowSpec ativa no momento."
    lines = ["Regras FlowSpec ativas:"]
    for rule_id, description, created_at in rows:
        lines.append(f"  [{rule_id}] {description} (anunciada {created_at})")
    return "\n".join(lines)
