"""Monitoramento de equipamentos por ping (Fase 8 — Operação de ISP / NOC).

Equivale ao monitoramento.py do spec, mas com uma correção importante: o
estado de cada equipamento (online/offline) fica PERSISTIDO no banco
(monitored_devices.current_status), não num set em memória. Assim a Nexus
não esquece quem estava caído ao reiniciar — e não dispara um alerta
duplicado de queda no primeiro ciclo após restart.

Detecta transições e age só nelas:
  - online/unknown -> offline: abre chamado (device_outages) + notifica queda.
  - offline -> online: baixa o chamado + notifica normalização.
  - estável: nada (não re-notifica a cada ciclo).
"""

import ipaddress
import platform
import subprocess

from database.db import (
    list_monitored_devices,
    log_event,
    open_device_outage,
    resolve_device_outage,
    set_device_status,
)
from tools import notify

_SYSTEM = platform.system()


def ping(ip: str, count: int = 2, timeout: int = 4) -> bool:
    """True se o host responde ao ping. Flags por plataforma; sem shell=True;
    subprocess timeout limita o tempo total mesmo com host inalcançável. IP
    inválido é tratado como inalcançável (evita passar argumento arbitrário)."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    if _SYSTEM == "Darwin":
        # macOS: -t é timeout total em segundos antes do ping sair.
        cmd = ["ping", "-c", str(count), "-t", str(timeout), ip]
    else:
        # Linux: -W é o tempo de espera por resposta, em segundos.
        cmd = ["ping", "-c", str(count), "-W", str(timeout), ip]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout * count + 5
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
    return result.returncode == 0


def check_all_devices() -> list[str]:
    """Faz ping em cada equipamento habilitado e age nas transições de estado.
    Retorna a lista de transições desta passagem (vazia se tudo estável)."""
    transitions: list[str] = []
    for row in list_monitored_devices(only_enabled=True):
        (device_id, name, ip, _model, location, _type, _enabled,
         current_status, _last_change) = row

        new_status = "online" if ping(ip) else "offline"
        if new_status == current_status:
            continue  # estável — não re-notifica

        set_device_status(device_id, new_status)
        label = name or device_id

        if new_status == "offline":
            open_device_outage(device_id, ip, name, reason="Sem resposta ao ping")
            log_event("device_down", ip, f"device={device_id} name={name!r}", action_taken="queda")
            notify.send_notification(
                "Nexus: equipamento CAIU",
                f"🔴 *{label}* — `{ip}`\n🗺️ Local: {location or '—'}\n⏰ Sem resposta ao ping — verificar.",
            )
            transitions.append(f"DOWN {device_id} ({ip})")
        elif current_status == "offline":
            # offline -> online: recuperação real de uma queda anterior.
            resolve_device_outage(device_id)
            log_event("device_up", ip, f"device={device_id} name={name!r}", action_taken="normalizado")
            notify.send_notification(
                "Nexus: equipamento VOLTOU",
                f"🟢 *{label}* — `{ip}`\nConexão restabelecida.",
            )
            transitions.append(f"UP {device_id} ({ip})")
        else:
            # unknown -> online: primeira observação saudável, sem alarme.
            log_event("device_up", ip, f"device={device_id} name={name!r}", action_taken="online_inicial")

    return transitions
