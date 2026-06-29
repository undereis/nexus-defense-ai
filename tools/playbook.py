"""Playbooks de resposta escalonada a ataques.

Mapeia tipos de ataque detectados → sequência de ações proporcionais à
ameaça, executadas automaticamente até o nível configurado em
PLAYBOOK_AUTO_LEVEL:

  Nível 1 — Throttle:     rate limiting (primeiros sinais, reversível)
  Nível 2 — Isolamento:   block_ip local (ameaça confirmada)
  Nível 3 — FlowSpec:     BGP upstream (impacto volumétrico; SEMPRE gated)
  Nível 4 — Blacklist:    AbuseIPDB + notificação (escalada global)

AUTONOMIA CONTROLADA: PLAYBOOK_AUTO_LEVEL define até qual nível o sistema
age SEM pedir confirmação humana. Padrão = 0 (só avalia e sugere).
Nível 3 (BGP FlowSpec) NUNCA executa automaticamente — a barreira é
programática (hard-capped em 2 no auto_cap abaixo), independente do
que PLAYBOOK_AUTO_LEVEL diga.
"""

import json

from config import PLAYBOOK_AUTO_LEVEL
from database.db import (
    get_threat_history,
    list_playbook_executions,
    log_event,
    record_playbook_execution,
)
from tools import firewall
from tools.threat_intel import record_confirmed_isolation, reputation_score

# ---------- definições de playbooks ----------

# base_level: nível mínimo de resposta para o tipo de ataque (independente
# do score de reincidência).
# reoffender_bump: se True, um IP com score >= 10 sobe +1 nível automático.
ATTACK_PLAYBOOKS: dict[str, dict] = {
    "port_scan": {
        "description": "Varredura de portas sequencial detectada",
        "base_level": 1,
        "reoffender_bump": True,
    },
    "brute_force": {
        "description": "Força bruta em credenciais (SSH/FTP/MySQL/RDP…)",
        "base_level": 2,
        "reoffender_bump": False,
    },
    "honeypot_trap": {
        "description": "Conexão confirmada a porta-armadilha (honeypot)",
        "base_level": 2,
        "reoffender_bump": False,
    },
    "honeynet_violation": {
        "description": "Tráfego em segmento honeynet (zona morta)",
        "base_level": 2,
        "reoffender_bump": False,
    },
    "honeytoken_trigger": {
        "description": "Credencial-isca ou arquivo-isca acessado",
        "base_level": 2,
        "reoffender_bump": False,
    },
    "ddos_volumetric": {
        "description": "DDoS volumétrico — saturação de link",
        "base_level": 2,
        "reoffender_bump": True,
    },
    "web_attack": {
        "description": "Ataque web (SQLi/XSS/RCE detectado via DPI)",
        "base_level": 2,
        "reoffender_bump": False,
    },
    "recon_confirmed": {
        "description": "Reconhecimento confirmado por múltiplas fontes",
        "base_level": 1,
        "reoffender_bump": True,
    },
}

_LEVEL_NAMES = {
    1: "throttle (rate limiting)",
    2: "isolamento local",
    3: "BGP FlowSpec upstream (SEMPRE gated)",
    4: "blacklist global (AbuseIPDB + notificação)",
}

# Nível máximo que pode ser auto-executado — 3 é programaticamente excluído.
_AUTO_CAP = 2


# ---------- funções públicas ----------

def list_playbooks() -> str:
    """Lista todos os playbooks configurados, seus níveis de resposta e o
    nível de autonomia atual."""
    auto = PLAYBOOK_AUTO_LEVEL
    auto_note = (
        "só avalia e sugere (PLAYBOOK_AUTO_LEVEL=0)"
        if auto == 0
        else f"executa automaticamente até nível {min(auto, _AUTO_CAP)} "
             f"(nível 3 sempre requer confirmação humana)"
    )
    lines = [
        f"Playbooks de resposta — {auto_note}.",
        "",
        "Tipos de ataque e resposta base:",
    ]
    for attack_type, pb in ATTACK_PLAYBOOKS.items():
        bump_note = " (+1 nível se reincidente)" if pb["reoffender_bump"] else ""
        lines.append(
            f"  {attack_type}: nível {pb['base_level']}{bump_note}"
            f" — {pb['description']}"
        )
    lines += [
        "",
        "Níveis:",
        "  1 = throttle (rate limiting reversível)",
        "  2 = isolamento local total",
        "  3 = BGP FlowSpec upstream (gate obrigatório)",
        "  4 = blacklist global AbuseIPDB + notificação",
    ]
    return "\n".join(lines)


def _get_score(ip: str) -> int:
    history = get_threat_history(ip)
    if not history:
        return 0
    _, _, times_flagged, times_isolated = history
    return reputation_score(times_flagged, times_isolated)


def _determine_level(attack_type: str, score: int) -> int:
    """Calcula o nível de resposta para o par (attack_type, score).
    Exportado para facilitar testes."""
    pb = ATTACK_PLAYBOOKS.get(attack_type, {"base_level": 1, "reoffender_bump": True})
    level = pb["base_level"]
    if pb.get("reoffender_bump") and score >= 10:
        level = min(level + 1, 4)
    return level


def evaluate_and_respond(ip: str, attack_type: str, metadata: dict | None = None) -> str:
    """Avalia a ameaça de um IP e executa a resposta proporcional até o
    nível permitido por PLAYBOOK_AUTO_LEVEL.

    Retorna um relatório completo: nível determinado, ações executadas
    automaticamente, e o que ainda está sugerido para decisão manual.

    metadata é opcional — se fornecido, enriquece as mensagens de log
    (ex: {'service': 'ssh', 'port': 22, 'z_score': 4.2})."""
    score = _get_score(ip)
    determined_level = _determine_level(attack_type, score)
    pb = ATTACK_PLAYBOOKS.get(attack_type)
    attack_desc = pb["description"] if pb else attack_type

    # BARREIRA PROGRAMÁTICA: nível 3 (BGP FlowSpec) nunca é auto-executado.
    # _AUTO_CAP = 2; qualquer PLAYBOOK_AUTO_LEVEL >= 3 só avança até 2.
    effective_auto = min(PLAYBOOK_AUTO_LEVEL, _AUTO_CAP, determined_level)

    actions_taken = []
    lines = [
        f"PLAYBOOK [{attack_type.upper()}] — {ip}",
        f"  Ameaça: {attack_desc}",
        f"  Score de reincidência: {score}",
        f"  Nível determinado: {determined_level} ({_LEVEL_NAMES.get(determined_level, '?')})",
        f"  Nível auto-executado: {effective_auto}",
        "",
    ]

    if effective_auto >= 1:
        result = firewall.rate_limit_ip(
            ip,
            reason=f"Playbook automático: {attack_type}",
            connections_per_second=10,
        )
        actions_taken.append(f"nível 1 (throttle): {result}")
        lines.append(f"  ✓ Nível 1 executado: {result}")

    if effective_auto >= 2:
        result = firewall.block_ip(
            ip,
            reason=f"Playbook automático: {attack_type} (score {score})",
        )
        record_confirmed_isolation(ip, f"Playbook automático: {attack_type}")
        actions_taken.append(f"nível 2 (isolamento): {result}")
        lines.append(f"  ✓ Nível 2 executado: {result}")

    if effective_auto >= 4:
        try:
            from tools import threat_feeds
            categories = threat_feeds.categorize_isolation_reason(attack_type)
            comment = (
                f"Isolado pela Nexus Defense AI — playbook automático: {attack_type}. "
                f"Score de reincidência: {score}."
            )
            report_result = threat_feeds.report_to_abuseipdb(ip, categories, comment)
            actions_taken.append(f"nível 4 (AbuseIPDB): {report_result}")
            lines.append(f"  ✓ Nível 4 executado: {report_result}")
        except Exception as exc:
            lines.append(f"  ! Nível 4 (report) falhou: {exc}")

    # Ações que não foram auto-executadas mas são sugeridas
    if determined_level > effective_auto:
        lines.append("")
        lines.append("  Ações sugeridas (requerem decisão manual):")
        if determined_level >= 2 and effective_auto < 2:
            lines.append(f"    → Nível 2: isolate_ip('{ip}') — isolamento local total")
        if determined_level >= 3:
            lines.append(
                "    → Nível 3: propose_bgp_flowspec_block — upstream block "
                "(REQUER gate de confirmação — nunca automático)"
            )
        if determined_level >= 4 and effective_auto < 4:
            lines.append(
                f"    → Nível 4: report_ip_to_abuseipdb('{ip}', '...') — blacklist global"
            )
        if PLAYBOOK_AUTO_LEVEL < determined_level:
            lines.append(
                f"\n    Para aumentar a autonomia: PLAYBOOK_AUTO_LEVEL="
                f"{min(determined_level, _AUTO_CAP)} no .env"
            )

    if effective_auto == 0 and PLAYBOOK_AUTO_LEVEL == 0:
        lines.append("  (Nenhuma ação automática — PLAYBOOK_AUTO_LEVEL=0.)")

    log_event(
        "playbook_evaluated", ip,
        f"attack_type={attack_type} level_determined={determined_level} "
        f"level_auto={effective_auto} score={score}",
        action_taken=(
            f"nível {effective_auto} executado" if effective_auto > 0 else "apenas avaliado"
        ),
    )
    record_playbook_execution(ip, attack_type, effective_auto, actions_taken)

    return "\n".join(lines)


def describe_playbook_history(ip: str | None = None, limit: int = 20) -> str:
    """Lista os playbooks executados recentemente. Se ip for fornecido,
    filtra apenas os registros desse IP."""
    rows = list_playbook_executions(ip, limit)
    if not rows:
        target = f" para {ip}" if ip else ""
        return f"Nenhum playbook executado ainda{target}."
    target = f" para {ip}" if ip else ""
    lines = [f"Histórico de playbooks{target} ({len(rows)} registro(s)):"]
    for _ip, attack_type, level_reached, actions_json, triggered_at in rows:
        try:
            actions = json.loads(actions_json)
            summary = "; ".join(a[:60] for a in actions[:2]) if actions else "só avaliado"
        except Exception:
            summary = str(actions_json)[:80]
        lines.append(
            f"  [{triggered_at}] {_ip} — {attack_type} → "
            f"nível {level_reached}: {summary}"
        )
    return "\n".join(lines)
