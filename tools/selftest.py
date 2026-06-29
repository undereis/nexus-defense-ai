"""Auto-diagnóstico de prontidão da Nexus (Frente F).

Responde, num relatório só, "está tudo no ar e configurado?": núcleo (DB,
integridade da auditoria, backend de firewall), integrações (Mikrotik, Telegram,
Slack/webhook, BrbOS, feeds), estado das travas de segurança, operação do NOC
(Fase 8) e defesa ativa (honeypot, ações pendentes).

Read-only: só lê estado e formata. Cada checagem é isolada (uma falha não
derruba o resto). Marcadores: ✅ ok · ⚠️ desligado/não configurado (informativo,
não é erro) · ❌ algo quebrado que merece atenção.
"""

import config
from database.db import (
    get_conn,
    list_device_outages,
    list_monitored_devices,
    list_pending_actions,
    list_subscribers,
)


def _safe(fn, fallback="❌ erro ao checar"):
    try:
        return fn()
    except Exception as exc:  # diagnóstico nunca deve crashar
        return f"{fallback}: {exc}"


def _check_db() -> str:
    with get_conn() as conn:
        n = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    return f"✅ DB acessível ({n} eventos na auditoria)"


def _check_audit() -> str:
    from tools.audit import verify_chain
    r = verify_chain()
    if r.intact and not r.truncated:
        return f"✅ Auditoria íntegra ({r.verified_events} verificados, {r.legacy_events} legados)"
    if r.truncated:
        return f"❌ Auditoria possivelmente TRUNCADA — {r.checkpoint_note}"
    return f"❌ Auditoria QUEBRADA no evento id={r.broken_at_id}"


def _check_firewall() -> str:
    from tools import firewall
    if firewall._backend is None:
        return f"⚠️ Firewall sem backend para a plataforma '{firewall._SYSTEM}'"
    return f"✅ Firewall backend ativo ({firewall._SYSTEM})"


def _yn(flag: bool, on="LIGADO", off="desligado") -> str:
    return on if flag else off


def run_selftest() -> str:
    lines = ["═══ NEXUS — AUTODIAGNÓSTICO ═══", ""]

    lines.append("• Núcleo:")
    lines.append("   " + _safe(_check_db))
    lines.append("   " + _safe(_check_audit))
    lines.append("   " + _safe(_check_firewall))

    lines.append("")
    lines.append("• Integrações (configurado = pronto pra usar):")
    lines.append("   " + ("✅" if config.MIKROTIK_HOST else "⚠️") +
                 f" Mikrotik: {'configurado' if config.MIKROTIK_HOST else 'não configurado'}")

    def _telegram_line():
        from tools import telegram
        out = "✅ Telegram: envio configurado" if telegram.is_configured() else "⚠️ Telegram: não configurado"
        out += " | bidirecional " + ("✅" if telegram.webhook_configured() else "⚠️ desligado")
        return out
    lines.append("   " + _safe(_telegram_line))

    def _notify_line():
        from tools import notify
        return "✅ Slack/webhook: configurado" if notify.is_configured() else "⚠️ Slack/webhook: não configurado"
    lines.append("   " + _safe(_notify_line))

    lines.append("   " + ("✅" if config.BRBOS_HOST else "⚠️") +
                 f" BrbOS: {'configurado' if config.BRBOS_HOST else 'não configurado'}")
    feeds = [k for k, v in [("AbuseIPDB", config.ABUSEIPDB_API_KEY),
                            ("VirusTotal", config.VIRUSTOTAL_API_KEY),
                            ("Shodan", config.SHODAN_API_KEY)] if v]
    lines.append("   " + ("✅ Feeds threat intel: " + ", ".join(feeds) if feeds
                          else "⚠️ Feeds threat intel: nenhuma API key"))

    def _siem_line():
        from tools import siem
        return "✅ SIEM: " + siem.describe_status().replace("SIEM: ", "") if siem.is_enabled() \
            else "⚠️ SIEM: desligado"
    lines.append("   " + _safe(_siem_line))

    lines.append("")
    lines.append("• Travas de segurança (off por padrão é o esperado):")
    lines.append(f"   Exploração ativa: {_yn(config.ALLOW_ACTIVE_EXPLOITATION)} | "
                 f"ASN block: {_yn(config.ALLOW_ASN_BLOCK)} | "
                 f"BrbOS block: {_yn(config.ALLOW_BRBOS_BLOCK)}")
    lines.append(f"   Detonação malware: {_yn(config.ALLOW_MALWARE_DETONATION)} | "
                 f"Auto-tune thresholds: {_yn(config.ALLOW_THRESHOLD_AUTOTUNE)} | "
                 f"Eng. social: {_yn(config.ALLOW_SOCIAL_ENGINEERING)}")
    lines.append(f"   Playbook auto-nível: {config.PLAYBOOK_AUTO_LEVEL} "
                 f"(nível 3/BGP FlowSpec NUNCA automático — _AUTO_CAP) | "
                 f"BGP: {'pipe ExaBGP configurado' if config.EXABGP_API_PIPE else 'sem pipe (não anuncia)'}")

    lines.append("")
    lines.append("• Operação NOC (Fase 8):")
    def _noc_line():
        subs = list_subscribers()
        blocked = sum(1 for s in subs if s[5] == "bloqueado_inadimplencia")
        devs = list_monitored_devices()
        offline = sum(1 for d in devs if d[7] == "offline")
        outages = len(list_device_outages("aberto", limit=200))
        return (f"   Assinantes: {len(subs)} ({blocked} bloqueados) | "
                f"Equipamentos: {len(devs)} ({offline} offline) | Quedas abertas: {outages}")
    lines.append(_safe(_noc_line))
    lines.append(f"   Cobrança automática: {_yn(config.SUBSCRIBER_BILLING_ENABLED)} "
                 f"(cap {config.SUBSCRIBER_BLOCK_MAX_BATCH}, dia {config.SUBSCRIBER_BLOCK_HOUR}h) | "
                 f"Monitor de equipamentos: "
                 f"{'a cada ' + str(config.DEVICE_MONITOR_INTERVAL) + 's' if config.DEVICE_MONITOR_INTERVAL > 0 else 'desligado'}")

    lines.append("")
    lines.append("• Defesa ativa:")
    def _honeypot_line():
        from tools import honeypot
        running = honeypot.list_running()
        return ("   Honeypot: " + ", ".join(f"{s}:{p}" for s, p in running)) if running \
            else "   Honeypot: nenhum serviço rodando"
    lines.append(_safe(_honeypot_line))
    def _pending_line():
        n = len(list_pending_actions())
        mark = "⚠️" if n else "✅"
        return f"   {mark} Ações de alto risco pendentes de confirmação: {n}"
    lines.append(_safe(_pending_line))

    return "\n".join(lines)
