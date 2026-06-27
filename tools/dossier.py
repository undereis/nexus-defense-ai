"""Dossiê unificado de atacante: junta TODAS as fontes de inteligência que
a Nexus já tem sobre um IP em um único relatório, em vez de precisar
consultar threat_intel, scan_findings, honeypot e geoip separadamente.

É o que transforma 5 fontes de dados isoladas em uma visão única de
"quem é esse IP, o que ele já fez, o que sabemos sobre a infraestrutura
dele, e de onde ele vem"."""

from database.db import (
    get_event_types_for_ip,
    get_findings_for_host,
    get_honeypot_services_for_ip,
    get_threat_history,
    list_honeypot_credentials_for_ip,
    list_honeypot_hits_for_ip,
)
from tools import fingerprint, geoip, mitre_attack
from tools.threat_intel import reputation_score


def build_dossier(ip: str) -> str:
    sections = [f"═══ DOSSIÊ DE ATAQUE: {ip} ═══", ""]

    # Geolocalização / ASN
    sections.append("📍 Origem:")
    sections.append("  " + geoip.describe_location(ip))
    sections.append("")

    # Threat intel (histórico de ataques de rede / DDoS)
    history = get_threat_history(ip)
    sections.append("🎯 Histórico de ataque (detecção por volume de tráfego):")
    if history:
        first_seen, last_seen, times_flagged, times_isolated = history
        score = reputation_score(times_flagged, times_isolated)
        sections.append(f"  Primeira vez visto: {first_seen}")
        sections.append(f"  Última vez visto: {last_seen}")
        sections.append(f"  Sinalizado: {times_flagged}x | Isolado: {times_isolated}x | Score: {score}")
        if score >= 10:
            sections.append("  -> REINCIDENTE CONHECIDO")
    else:
        sections.append("  Nenhum registro de ataque por volume de tráfego.")
    sections.append("")

    # Honeypot: conexões
    hp_hits = list_honeypot_hits_for_ip(ip)
    sections.append(f"🍯 Capturas em honeypot ({len(hp_hits)}):")
    if hp_hits:
        for port, service, timestamp in hp_hits[:10]:
            sections.append(f"  [{timestamp}] tentou {service} na porta {port}")
    else:
        sections.append("  Nenhuma conexão em honeypot.")
    sections.append("")

    # Honeypot: credenciais capturadas
    hp_creds = list_honeypot_credentials_for_ip(ip)
    sections.append(f"🔑 Credenciais capturadas ({len(hp_creds)}):")
    if hp_creds:
        for port, service, username, password, timestamp in hp_creds[:10]:
            sections.append(f"  [{timestamp}] {service}:{port} -> usuário={username!r} senha={password!r}")
    else:
        sections.append("  Nenhuma credencial capturada.")
    sections.append("")

    # Auditorias de segurança já feitas nesse IP/host
    findings = get_findings_for_host(ip)
    sections.append(f"🔍 Auditorias de segurança prévias neste IP ({len(findings)}):")
    if findings:
        for scan_type, summary, created_at in findings[:5]:
            preview = summary[:150].replace("\n", " ")
            sections.append(f"  [{created_at}] {scan_type}: {preview}...")
    else:
        sections.append("  Nenhuma auditoria (nmap/nikto/ssl/headers) já feita neste IP.")
    sections.append("")

    # Veredito consolidado
    severity_signals = []
    if history and reputation_score(history[2], history[3]) >= 10:
        severity_signals.append("reincidente em ataques de rede")
    if hp_hits:
        severity_signals.append(f"capturado em {len(hp_hits)} honeypot(s)")
    if hp_creds:
        severity_signals.append("tentou credenciais reais (possível credential stuffing)")
    if findings:
        severity_signals.append("já auditado anteriormente — correlacione vulnerabilidades")

    # MITRE ATT&CK: traduz os event_types e serviços de honeypot tocados
    # em técnicas reais do framework, em vez de só listar eventos crus.
    event_types = get_event_types_for_ip(ip)
    honeypot_services = get_honeypot_services_for_ip(ip)
    sections.append("🗺️ " + mitre_attack.summarize_ttps_for_ip(event_types, honeypot_services))
    sections.append("")

    # Fingerprint comportamental: outros IPs com o mesmo padrão de
    # portas/timing — possível mesmo atacante, IP diferente.
    sections.append("🫆 " + fingerprint.describe_similar_attackers(ip))
    sections.append("")

    sections.append("⚖️ Veredito:")
    if severity_signals:
        sections.append("  AMEAÇA CONFIRMADA: " + "; ".join(severity_signals) + ".")
    else:
        sections.append("  Sem sinais fortes de ameaça nas fontes disponíveis ainda.")

    return "\n".join(sections)
