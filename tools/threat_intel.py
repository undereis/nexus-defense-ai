"""Threat intelligence: memória institucional de atacantes.

Diferente da detecção em tempo real (tools/network_monitor.py), que só
vê a janela de segundos atual, este módulo dá à Nexus memória de longo
prazo: quais IPs já atacaram antes, quantas vezes, e há quanto tempo.
Isso permite reagir mais rápido a reincidentes — um IP que já foi
isolado antes não precisa esperar o mesmo processo de novo.
"""

from database.db import (
    get_findings_for_host,
    get_threat_history,
    list_repeat_offenders,
    record_threat_flag,
    record_threat_isolation,
)


def reputation_score(times_flagged: int, times_isolated: int) -> int:
    """Pontuação simples de reincidência: isolamentos pesam mais que
    sinalizações isoladas, porque representam ameaça confirmada."""
    return times_isolated * 10 + times_flagged * 2


def is_repeat_offender(ip: str, score_threshold: int = 10) -> bool:
    """True se o IP já tem histórico de ataque suficiente para ser tratado
    como ameaça conhecida, não como caso novo."""
    history = get_threat_history(ip)
    if not history:
        return False
    _, _, times_flagged, times_isolated = history
    return reputation_score(times_flagged, times_isolated) >= score_threshold


def describe_history(ip: str) -> str:
    """Texto legível com o histórico de um IP, para a Nexus explicar ao criador."""
    history = get_threat_history(ip)
    if not history:
        return f"{ip} não tem histórico registrado — é a primeira vez que aparece."

    first_seen, last_seen, times_flagged, times_isolated = history
    score = reputation_score(times_flagged, times_isolated)
    lines = [
        f"Histórico de {ip}:",
        f"  Primeira vez visto: {first_seen}",
        f"  Última vez visto: {last_seen}",
        f"  Sinalizado como suspeito: {times_flagged}x",
        f"  Isolado pelo firewall: {times_isolated}x",
        f"  Pontuação de reincidência: {score}",
    ]
    if score >= 10:
        lines.append("  -> REINCIDENTE CONHECIDO: tratar com prioridade máxima.")
    return "\n".join(lines)


def correlate(ip: str) -> str:
    """Cruza o histórico de ataque de um IP com qualquer auditoria de
    segurança já feita nesse mesmo endereço (nmap, nikto, ssl, headers).
    É o que transforma dois logs separados em inteligência de ameaça: se
    o IP que te atacou também já foi auditado, a Nexus sabe o que ele tem
    de exposto, não só que ele atacou."""
    history = describe_history(ip)
    findings = get_findings_for_host(ip)

    if not findings:
        return f"{history}\n\nNenhuma auditoria de segurança prévia registrada para {ip}."

    lines = [history, "", f"AUDITORIAS PRÉVIAS EM {ip} ({len(findings)} encontrada(s)):"]
    for scan_type, summary, created_at in findings:
        preview = summary[:200] + ("..." if len(summary) > 200 else "")
        lines.append(f"  [{created_at}] {scan_type}: {preview}")
    lines.append(
        "\n-> Este IP já foi auditado antes: use os achados acima para entender "
        "o que ele pode estar explorando ou de onde o ataque pode estar vindo."
    )
    return "\n".join(lines)


def describe_repeat_offenders(min_score: int = 1) -> str:
    """Lista todos os IPs com histórico de ataque, do mais reincidente ao menos."""
    rows = list_repeat_offenders(min_score)
    if not rows:
        return "Nenhum IP com histórico de ataque registrado ainda."
    lines = ["IPs com histórico de ataque (mais reincidentes primeiro):"]
    for ip, times_flagged, times_isolated, last_seen in rows:
        score = reputation_score(times_flagged, times_isolated)
        lines.append(
            f"  {ip}: {times_isolated}x isolado, {times_flagged}x sinalizado "
            f"(score {score}, visto por último em {last_seen})"
        )
    return "\n".join(lines)
