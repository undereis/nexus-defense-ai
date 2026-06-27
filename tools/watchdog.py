"""Watchdog: auto-recuperação dos honeypots configurados.

Threads de honeypot podem morrer silenciosamente (erro de socket,
exceção não tratada em algum handler, etc). Sem isso, a Nexus podia
achar que ainda está "protegida" por um honeypot que já caiu há
horas. O watchdog verifica periodicamente e reinicia o que faltar,
notificando para o criador saber que algo precisou ser reerguido.
"""

from config import HONEYPOT_ENABLED, HONEYPOT_SERVICES
from database.db import log_event
from tools import honeypot, notify


def expected_services() -> list[tuple[str, int]]:
    """Lê HONEYPOT_SERVICES e retorna a lista de (service, port) que
    deveriam estar rodando, se HONEYPOT_ENABLED estiver ligado."""
    if not HONEYPOT_ENABLED:
        return []
    expected = []
    for entry in HONEYPOT_SERVICES.split(","):
        entry = entry.strip()
        if not entry:
            continue
        service, _, port_str = entry.partition(":")
        if service and port_str.isdigit():
            expected.append((service, int(port_str)))
    return expected


_FAILURE_MARKERS = ("Falha ao iniciar", "não respondeu em")


def check_and_heal() -> list[str]:
    """Verifica se cada honeypot esperado está rodando; reinicia os que
    caíram. Retorna a lista de (service:port) que FORAM DE FATO
    reerguidos nesta checagem (vazia se tudo estava ok).

    honeypot.start() agora confirma o bind antes de retornar, então o
    resultado é checado aqui — sem isso, uma falha persistente (porta
    ocupada por outro processo) fazia o watchdog "curar" para sempre algo
    que nunca subiu de verdade, notificando sucesso falso a cada ciclo."""
    wanted = expected_services()
    if not wanted:
        return []

    running = set(honeypot.list_running())
    healed = []
    failed = []

    for service, port in wanted:
        if (service, port) not in running and not honeypot.is_manually_stopped(service, port):
            result = honeypot.start(service, port)
            if any(marker in result for marker in _FAILURE_MARKERS):
                failed.append(f"{service}:{port}")
                log_event(
                    "watchdog_heal_failed", None,
                    f"Honeypot {service}:{port} continua caído: {result}",
                    action_taken="falhou",
                )
                continue
            healed.append(f"{service}:{port}")
            log_event(
                "watchdog_healed", None,
                f"Honeypot {service}:{port} estava caído, reiniciado. {result}",
                action_taken="recuperado",
            )

    if healed:
        notify.send_notification(
            "Nexus: watchdog reergueu serviço(s) caído(s)",
            f"Honeypot(s) reiniciado(s): {', '.join(healed)}",
        )
    if failed:
        notify.send_notification(
            "Nexus: watchdog NÃO conseguiu reerguer serviço(s)",
            f"Honeypot(s) que continuam caídos (provável conflito de porta): {', '.join(failed)}. "
            "Verifique se outro processo está usando essas portas.",
        )

    return healed
