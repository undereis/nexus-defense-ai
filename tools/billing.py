"""Bloqueio de inadimplentes (Fase 8 — Operação de ISP / NOC).

Substitui o stack Node.js + netmiko do spec original por um subsistema do
Nexus que reaproveita o que já existe:

  - bloqueio/desbloqueio via API nativa RouterOS (tools/mikrotik.py), não SSH;
  - persistência + auditoria hash-chain (database/db.py);
  - notificação multicanal (tools/notify.py → Slack/webhook/Telegram).

Fonte de cobrança atrás de um adaptador (BillingSource): hoje LÊ da tabela
local `subscribers`; amanhã pode ler do sistema real (PHPMaker/API) sem mudar
o resto. Selecionada por BILLING_SOURCE.

Salvaguardas (mesma filosofia do _AUTO_CAP do playbook):
  - CAP de lote: um ciclo que bloquearia mais que SUBSCRIBER_BLOCK_MAX_BATCH
    de uma vez NÃO bloqueia ninguém — só alerta (proteção contra erro na
    cobrança derrubar a base inteira).
  - Proteção de infra: nunca bloqueia loopback nem IP crítico próprio
    (_is_safe_to_block, análogo de honeypot._is_safe_to_isolate).
  - Idempotência: a régua do MikroTik dedupa pelo comentário, e o ciclo só
    olha assinantes 'ativo'/'bloqueado' conforme o lado.
"""

import ipaddress

from config import (
    BILLING_SOURCE,
    SUBSCRIBER_BLOCK_DAYS,
    SUBSCRIBER_BLOCK_MAX_BATCH,
)
from database.db import (
    get_subscriber,
    list_delinquent_subscribers,
    list_reactivatable_subscribers,
    log_event,
    record_subscriber_action,
    set_subscriber_status,
)
from tools import mikrotik, notify
from tools.infrastructure import is_critical_ip

# Marcadores de falha nas mensagens de retorno do tools/mikrotik (que sempre
# devolve string, nunca levanta). Se algum aparecer, o bloqueio NÃO ocorreu.
_MIKROTIK_FAILURE_MARKERS = ("Falha ao comunicar", "não configurado", "inválida")


def _is_safe_to_block(ip: str) -> bool:
    """Nunca bloqueia loopback nem IP crítico da própria infraestrutura —
    defesa em profundidade contra cortar acesso de um servidor/roteador da
    Xfiber por engano (mesma proteção do auto-isolamento)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback:
        return False
    if is_critical_ip(ip):
        return False
    return True


def _is_mikrotik_failure(result: str) -> bool:
    return any(marker in result for marker in _MIKROTIK_FAILURE_MARKERS)


# ---------- adaptador de fonte de cobrança ----------

class BillingSource:
    """Interface da fonte de dados de inadimplência. Cada item é um dict com
    pelo menos: subscriber_id, name, ip_address, device_host, interface."""

    def list_delinquent(self, min_days: int) -> list[dict]:
        raise NotImplementedError

    def list_reactivated(self) -> list[dict]:
        raise NotImplementedError


class LocalBillingSource(BillingSource):
    """Lê da tabela local `subscribers` (invoice_status/days_overdue). Funciona
    já hoje e é totalmente testável sem cobrança externa."""

    def list_delinquent(self, min_days: int) -> list[dict]:
        rows = list_delinquent_subscribers(min_days)
        return [
            {"subscriber_id": sid, "name": name, "ip_address": ip,
             "device_host": host, "interface": iface, "days_overdue": days}
            for (sid, name, ip, host, iface, days) in rows
        ]

    def list_reactivated(self) -> list[dict]:
        rows = list_reactivatable_subscribers()
        return [
            {"subscriber_id": sid, "name": name, "ip_address": ip,
             "device_host": host, "interface": iface}
            for (sid, name, ip, host, iface) in rows
        ]


class ExternalBillingSource(BillingSource):
    """Stub do adaptador para o sistema real de cobrança (PHPMaker/API). Ainda
    não wirado — recusa explicitamente em vez de fingir que funciona."""

    _MSG = ("Fonte externa de cobrança não configurada (BILLING_SOURCE=external "
            "sem adaptador wirado). Use BILLING_SOURCE=local ou wire o adaptador.")

    def list_delinquent(self, min_days: int) -> list[dict]:
        raise RuntimeError(self._MSG)

    def list_reactivated(self) -> list[dict]:
        raise RuntimeError(self._MSG)


def get_billing_source() -> BillingSource:
    if BILLING_SOURCE == "external":
        return ExternalBillingSource()
    return LocalBillingSource()


# ---------- bloqueio/desbloqueio de um assinante ----------

def block_subscriber(sub: dict, reason: str = "") -> tuple[bool, str]:
    """Bloqueia um assinante no MikroTik e atualiza estado + auditoria.
    Retorna (sucesso, detalhe). Recusa IP de infra sem tocar no firewall."""
    sid = sub["subscriber_id"]
    ip = sub["ip_address"]
    reason = reason or f"{sub.get('days_overdue', '?')} dias de atraso"

    if not _is_safe_to_block(ip):
        record_subscriber_action(sid, "bloqueio_recusado", f"IP protegido/infra: {ip}")
        log_event("subscriber_block_refused", ip, f"sid={sid} motivo=infra_protegida", action_taken="recusado")
        return False, f"RECUSADO {sid} ({ip}): IP de infraestrutura/loopback nunca é bloqueado."

    result = mikrotik.block_subscriber_ip(ip)
    if _is_mikrotik_failure(result):
        record_subscriber_action(sid, "bloqueio_falhou", result)
        log_event("subscriber_block_failed", ip, f"sid={sid} {result}", action_taken="falhou")
        return False, f"FALHA {sid} ({ip}): {result}"

    set_subscriber_status(sid, "bloqueado_inadimplencia")
    record_subscriber_action(sid, "bloqueado", reason)
    return True, f"OK {sid} ({ip}): {result}"


def unblock_subscriber(sub: dict, reason: str = "pagamento confirmado") -> tuple[bool, str]:
    """Desbloqueia um assinante no MikroTik e reativa o estado + auditoria."""
    sid = sub["subscriber_id"]
    ip = sub["ip_address"]

    result = mikrotik.unblock_subscriber_ip(ip)
    if _is_mikrotik_failure(result):
        record_subscriber_action(sid, "desbloqueio_falhou", result)
        log_event("subscriber_unblock_failed", ip, f"sid={sid} {result}", action_taken="falhou")
        return False, f"FALHA {sid} ({ip}): {result}"

    set_subscriber_status(sid, "ativo")
    record_subscriber_action(sid, "desbloqueado", reason)
    return True, f"OK {sid} ({ip}): {result}"


def _subscriber_to_dict(row) -> dict:
    sid, name, ip, host, iface, status, invoice_status, days = row
    return {"subscriber_id": sid, "name": name, "ip_address": ip,
            "device_host": host, "interface": iface, "status": status,
            "invoice_status": invoice_status, "days_overdue": days}


def block_subscriber_by_id(subscriber_id: str, reason: str = "bloqueio manual") -> str:
    """Bloqueio ad-hoc de um assinante pelo id (tool do agente)."""
    row = get_subscriber(subscriber_id)
    if row is None:
        return f"Assinante '{subscriber_id}' não encontrado."
    sub = _subscriber_to_dict(row)
    if sub["status"] == "bloqueado_inadimplencia":
        return f"Assinante '{subscriber_id}' já está bloqueado (nada a fazer)."
    _ok, detail = block_subscriber(sub, reason=reason)
    return detail


def unblock_subscriber_by_id(subscriber_id: str, reason: str = "desbloqueio manual") -> str:
    """Desbloqueio ad-hoc de um assinante pelo id (tool do agente)."""
    row = get_subscriber(subscriber_id)
    if row is None:
        return f"Assinante '{subscriber_id}' não encontrado."
    sub = _subscriber_to_dict(row)
    _ok, detail = unblock_subscriber(sub, reason=reason)
    return detail


# ---------- ciclo diário ----------

def run_billing_cycle(min_days: int | None = None, max_batch: int | None = None,
                      dry_run: bool = False) -> str:
    """Roda um ciclo de cobrança: bloqueia inadimplentes e reativa quem pagou.

    dry_run=True apenas LISTA o que faria, sem tocar no firewall. O CAP de
    segurança aborta o ciclo inteiro se o número de inadimplentes for anormal.
    """
    min_days = SUBSCRIBER_BLOCK_DAYS if min_days is None else min_days
    max_batch = SUBSCRIBER_BLOCK_MAX_BATCH if max_batch is None else max_batch
    source = get_billing_source()

    try:
        delinquent = source.list_delinquent(min_days)
        reactivated = source.list_reactivated()
    except Exception as exc:
        msg = f"Ciclo de cobrança abortado: falha ao consultar a fonte de cobrança: {exc}"
        log_event("billing_cycle_error", None, str(exc), action_taken="abortado")
        return msg

    # CAP de segurança — antes de bloquear qualquer um.
    if len(delinquent) > max_batch:
        msg = (
            f"CICLO ABORTADO POR SEGURANÇA: {len(delinquent)} inadimplentes excede o cap "
            f"de {max_batch}. NINGUÉM foi bloqueado — isso costuma indicar erro na fonte de "
            f"cobrança (não a base inteira ficou inadimplente de uma vez). Revise; se for "
            f"legítimo, suba SUBSCRIBER_BLOCK_MAX_BATCH deliberadamente."
        )
        log_event("billing_cycle_capped", None,
                  f"delinquent={len(delinquent)} cap={max_batch}", action_taken="abortado")
        notify.send_notification("Nexus: ciclo de cobrança ABORTADO (cap de segurança)", msg)
        return msg

    if dry_run:
        lines = [f"[DRY-RUN] Ciclo de cobrança (atraso >= {min_days}d) — nada foi alterado:"]
        lines.append(f"  Bloquearia {len(delinquent)} inadimplente(s):")
        for s in delinquent:
            lines.append(f"    - {s['subscriber_id']} ({s['ip_address']}, {s.get('days_overdue', '?')}d)")
        lines.append(f"  Reativaria {len(reactivated)}: "
                     f"{', '.join(s['subscriber_id'] for s in reactivated) or '(nenhum)'}")
        return "\n".join(lines)

    blocked, block_failed = [], []
    for sub in delinquent:
        ok, _detail = block_subscriber(sub, reason=f"{sub.get('days_overdue', '?')} dias de atraso")
        (blocked if ok else block_failed).append(sub["subscriber_id"])

    reactivated_ok, reactivate_failed = [], []
    for sub in reactivated:
        ok, _detail = unblock_subscriber(sub)
        (reactivated_ok if ok else reactivate_failed).append(sub["subscriber_id"])

    summary_lines = [
        f"Ciclo de cobrança concluído (atraso >= {min_days}d):",
        f"  Bloqueados: {len(blocked)}" + (f" — {', '.join(blocked)}" if blocked else ""),
        f"  Reativados: {len(reactivated_ok)}" + (f" — {', '.join(reactivated_ok)}" if reactivated_ok else ""),
    ]
    if block_failed:
        summary_lines.append(f"  FALHAS de bloqueio: {', '.join(block_failed)}")
    if reactivate_failed:
        summary_lines.append(f"  FALHAS de reativação: {', '.join(reactivate_failed)}")
    summary = "\n".join(summary_lines)

    log_event("billing_cycle_done", None,
              f"blocked={len(blocked)} reactivated={len(reactivated_ok)} "
              f"block_failed={len(block_failed)} reactivate_failed={len(reactivate_failed)}",
              action_taken="concluido")
    notify.send_notification("Nexus: ciclo de cobrança", summary)
    return summary
