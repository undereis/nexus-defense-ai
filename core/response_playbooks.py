"""Playbooks determinísticos de resposta (Prioridade 9).

Cada playbook é declarativo: gatilho, evidências necessárias, ações recomendadas
(passos humanos) e ações CANDIDATAS (tipos de ação do Control Plane). O
diferencial: as ações candidatas são classificadas em tempo real pelo PRÓPRIO
Policy Engine — AUTO (ALLOW) / APROVAÇÃO (REQUIRE_APPROVAL) / DRY-RUN (modo
lab/replay) / BLOQUEADA (DENY) — em vez de duplicar a regra. Assim o "relatório
final" reflete o estado real (modo operacional, toggles ALLOW_*, papel, alvo,
inventário) na hora.

Distinto de tools/playbook.py (motor de ESCALONAMENTO automático por nível com
_AUTO_CAP). Aqui é o guia de RESPOSTA: o que fazer, com que evidência, e o que a
governança permite agora. Não executa nada — só planeja e classifica.
"""

from dataclasses import dataclass

from core import control_plane as cp, operating_mode
from core.models import Decision
from core.policy_engine import evaluate as _evaluate


@dataclass(frozen=True)
class Playbook:
    key: str
    name: str
    trigger: str
    required_evidence: tuple[str, ...]
    recommended_actions: tuple[str, ...]
    # (action_type, descrição) — classificadas pela policy engine.
    candidate_actions: tuple[tuple[str, str], ...]
    notes: str = ""


PLAYBOOKS: dict[str, Playbook] = {
    "ddos": Playbook(
        "ddos", "DDoS volumétrico",
        "Volume de conexões muito acima da baseline, de um ou muitos IPs, saturando recurso/uplink.",
        ("contagem de conexões por IP acima do threshold", "janela temporal do pico",
         "confirmação de que não é tráfego legítimo (evento/cliente)"),
        ("Throttle/rate-limit nos IPs ofensivos", "Isolar os IPs confirmados",
         "Se saturar o uplink, escalar para BGP FlowSpec na borda", "Abrir incidente e notificar"),
        (("block_ip", "isolar os IPs ofensivos"),
         ("bgp_flowspec", "anunciar FlowSpec para drop na borda (uplink saturado)"),
         ("asn_block", "bloquear o ASN de origem se o ataque for concentrado")),
    ),
    "suspect_ip": Playbook(
        "suspect_ip", "IP suspeito / reincidente",
        "IP com reputação ruim (threat intel) ou histórico de isolamento reaparece.",
        ("reputação em threat intel", "histórico de isolamento (check_threat_history)",
         "correlação com honeypot/scan"),
        ("Consultar o dossiê do IP", "Isolar se confirmado", "Registrar no incidente relacionado"),
        (("block_ip", "isolar o IP suspeito confirmado"),),
    ),
    "honeypot_hit": Playbook(
        "honeypot_hit", "Acesso a honeypot",
        "Conexão a uma porta-armadilha — não há motivo legítimo, é evidência direta de varredura.",
        ("registro de honeypot_hit (ip/porta/serviço)", "IP de origem"),
        ("Isolar o IP imediatamente", "Abrir incidente", "Reportar reputação (AbuseIPDB)"),
        (("block_ip", "isolar imediatamente — honeypot é evidência direta"),),
    ),
    "credential_stuffing": Playbook(
        "credential_stuffing", "Credential stuffing / brute force entrante",
        "Muitas tentativas de login falhas, possivelmente contra várias contas, de uma origem.",
        ("logs de autenticação com taxa de falha", "lista de usuários alvo",
         "origem (IP/ASN) concentrada"),
        ("Isolar a origem", "Rate-limit no Mikrotik/borda", "Forçar reset de senha das contas visadas",
         "Abrir incidente"),
        (("block_ip", "isolar a origem das tentativas"),
         ("mikrotik_write", "aplicar rate-limit/regra no Mikrotik")),
    ),
    "device_down": Playbook(
        "device_down", "Queda de equipamento",
        "Equipamento monitorado (Microkit/OLT/switch) parou de responder a ping.",
        ("device_outage aberto", "duração da queda", "último status conhecido"),
        ("Reconfirmar o estado (re-ping)", "Checar dependências (uplink/energia)",
         "Abrir incidente e notificar NOC", "Acionar campo se persistir"),
        (("device_check", "reconfirmar o estado dos equipamentos"),),
    ),
    "firewall_drift": Playbook(
        "firewall_drift", "Drift do firewall",
        "O estado real do firewall diverge do que o banco espera (regra removida/adicionada por fora).",
        ("diff da reconciliação (reconcile)", "regras faltando ou sobrando", "quando foi detectado"),
        ("Rodar a reconciliação", "Reaplicar os bloqueios faltantes",
         "Investigar quem alterou (acesso indevido?)", "Abrir incidente se não explicado"),
        (("block_ip", "reaplicar bloqueios que sumiram do firewall"),),
    ),
    "mikrotik_change": Playbook(
        "mikrotik_change", "Mudança não esperada no Mikrotik",
        "Configuração do RouterOS mudou sem mudança planejada — possível comprometimento.",
        ("diff de configuração", "horário e usuário da mudança", "se houve janela de manutenção"),
        ("Confirmar se foi mudança autorizada", "Reverter o que não foi autorizado",
         "Rotacionar credenciais do Mikrotik", "Abrir incidente de alta severidade"),
        (("mikrotik_write", "reverter a mudança não autorizada"),),
    ),
    "authorized_brute_force": Playbook(
        "authorized_brute_force", "Brute force AUTORIZADO (pentest)",
        "Teste de senha autorizado contra um alvo no escopo do engajamento.",
        ("engagement_reference do engajamento", "alvo cadastrado no inventário (escopo)",
         "ALLOW_ACTIVE_EXPLOITATION ligado"),
        ("Confirmar autorização e janela", "Rodar o teste sob aprovação",
         "Registrar achados como evidência no incidente/relatório"),
        (("brute_force", "rodar o teste de credenciais no alvo autorizado"),),
    ),
}

_LABEL = {
    Decision.ALLOW: "AUTO",
    Decision.REQUIRE_APPROVAL: "APROVAÇÃO",
    Decision.DRY_RUN_ONLY: "DRY-RUN",
    Decision.DENY: "BLOQUEADA",
}


def list_playbooks() -> str:
    lines = ["Playbooks de resposta disponíveis:"]
    for pb in PLAYBOOKS.values():
        lines.append(f"  [{pb.key}] {pb.name} — gatilho: {pb.trigger}")
    return "\n".join(lines)


def get_playbook(key: str) -> Playbook | None:
    return PLAYBOOKS.get((key or "").strip().lower())


def build_plan(key: str, target: str = "", role: str = "") -> dict:
    """Classifica as ações candidatas pela policy engine. Retorna um dict
    estruturado (sem executar nada)."""
    pb = get_playbook(key)
    if pb is None:
        return {}
    mode = operating_mode.get_operating_mode()
    classified = []
    for action_type, desc in pb.candidate_actions:
        dec = _evaluate(cp.make_request(action_type, target=target, role=role))
        classified.append({
            "action_type": action_type, "description": desc,
            "decision": dec.decision.value, "label": _LABEL.get(dec.decision, "?"),
            "risk": dec.risk.value, "reason": dec.reason,
        })
    return {
        "key": pb.key, "name": pb.name, "trigger": pb.trigger, "mode": mode,
        "target": target or "—", "role": role or "admin (padrão)",
        "required_evidence": list(pb.required_evidence),
        "recommended_actions": list(pb.recommended_actions),
        "classified_actions": classified,
        "notes": pb.notes,
    }


def plan_report(key: str, target: str = "", role: str = "") -> str:
    """Relatório final do playbook: gatilho, evidências, ações recomendadas e a
    classificação das ações pela governança no estado atual."""
    plan = build_plan(key, target, role)
    if not plan:
        return f"Playbook '{key}' não encontrado. Use list_playbooks."
    lines = [
        f"Playbook: {plan['name']} (key={plan['key']})",
        f"Gatilho: {plan['trigger']}",
        "",
        "Evidências necessárias:",
        *[f"  - {e}" for e in plan["required_evidence"]],
        "",
        "Ações recomendadas:",
        *[f"  - {a}" for a in plan["recommended_actions"]],
        "",
        f"Classificação das ações (modo={plan['mode']}, papel={plan['role']}, alvo={plan['target']}):",
    ]
    for c in plan["classified_actions"]:
        lines.append(f"  [{c['label']}] {c['action_type']} ({c['risk']}) — {c['description']}")
        lines.append(f"        → {c['reason']}")
    lines += [
        "",
        "Legenda: AUTO=executa direto · APROVAÇÃO=exige confirmação fora de banda · "
        "DRY-RUN=modo lab/replay (não toca real) · BLOQUEADA=negada agora.",
    ]
    return "\n".join(lines)
