"""Reconciliação de estado do firewall: detecta e corrige "drift" entre
o que o banco acha que está bloqueado (estado intencional) e o que o pf
realmente tem na tabela do kernel (estado real).

Sem isso, um reboot, um `pfctl -F all` manual, ou qualquer reset do pf
faz os IPs isolados voltarem a ter acesso livre, silenciosamente — o
banco continua dizendo "bloqueado" mas ninguém percebe que não está
mais. Esse é o padrão de "reconciliation loop" comum em sistemas de
infraestrutura (ex: Kubernetes), aplicado ao firewall.
"""

from dataclasses import dataclass

from core import control_plane as cp
from database.db import list_blocked_ips
from tools import firewall


@dataclass
class ReconcileResult:
    checked: bool
    missing: list[str]  # deveriam estar bloqueados, não estão -> reaplicados
    extra: list[str]  # estão bloqueados mas o banco não sabia -> só reportado
    reapplied: list[str]
    reapply_errors: dict[str, str]

    @property
    def has_drift(self) -> bool:
        return bool(self.missing or self.extra)


def _reconcile_reapply(ip: str) -> cp.ActionResult:
    """CP-SD Fase 6R (endurecimento): a reaplicação de um bloqueio que sumiu do
    firewall (drift) passa pelo Control Plane, SEM fallback de identidade. Esta
    função NÃO instala Principal — EXIGE que o entrypoint automático confiável
    (reconcile_loop em main.py) já tenha instalado SERVICE_RECONCILE_PRINCIPAL.
    Sem contexto autenticado, a policy nega (allowed_actors) e nada é reaplicado.

    CONSEQUÊNCIA DOCUMENTADA: a tool humana `check_firewall_integrity` também
    chama check_and_reconcile, mas sob a identidade do humano — a DETECÇÃO de
    drift continua (read-only), porém a REAPLICAÇÃO é NEGADA (vai para
    reapply_errors com a razão do Control Plane). O humano vê o drift relatado,
    mas o conserto automático fica reservado ao loop de serviço. Defesa em
    profundidade: a trava dura de asset_registry.check_target barra infra
    própria crítica mesmo em ALLOW. firewall.block_ip só roda em ALLOW."""
    reason = "Reaplicado por reconciliação (drift detectado)"

    def _do_block(**_ignored) -> str:
        return firewall.block_ip(ip, reason=reason)

    req = cp.make_request(
        "reconcile.reapply_block", target=ip,
        params={"source": "reconcile", "reason": reason},
    )
    return cp.request_action(req, executor=_do_block, tool_name="cp_reconcile_reapply")


def check_and_reconcile(auto_reapply: bool = True) -> ReconcileResult:
    """Compara banco vs estado real do pf. Se algum IP que deveria estar
    bloqueado não está mais (drift), reaplica automaticamente por padrão."""
    actual = firewall.get_actual_blocked_ips()
    if actual is None:
        return ReconcileResult(checked=False, missing=[], extra=[], reapplied=[], reapply_errors={})

    intended = {row[0] for row in list_blocked_ips()}
    missing = sorted(intended - actual)
    extra = sorted(actual - intended)

    reapplied = []
    errors = {}
    if auto_reapply:
        for ip in missing:
            # CP-SD Fase 6R: reaplicação governada. "reapplied" só conta um IP
            # que o Control Plane PERMITIU e o firewall confirmou; DENY/
            # DRY_RUN_ONLY/falha caem em reapply_errors (comportamento honesto,
            # nunca conta como reaplicado o que não foi).
            res = _reconcile_reapply(ip)
            if (res.status is cp.ActionStatus.EXECUTED
                    and res.output.startswith("IP") and "sucesso" in res.output):
                reapplied.append(ip)
            else:
                errors[ip] = res.output

    return ReconcileResult(
        checked=True, missing=missing, extra=extra, reapplied=reapplied, reapply_errors=errors
    )


def describe(result: ReconcileResult) -> str:
    if not result.checked:
        return "Não foi possível verificar o estado do firewall (anchor pode não estar configurado)."
    if not result.has_drift:
        return "Estado do firewall consistente: nenhum drift detectado."

    lines = ["DRIFT DETECTADO no firewall:"]
    if result.missing:
        lines.append(
            f"  {len(result.missing)} IP(s) deveriam estar bloqueados e não estavam: "
            f"{', '.join(result.missing)}"
        )
    if result.reapplied:
        lines.append(f"  Reaplicados com sucesso: {', '.join(result.reapplied)}")
    if result.reapply_errors:
        for ip, err in result.reapply_errors.items():
            lines.append(f"  FALHA ao reaplicar {ip}: {err}")
    if result.extra:
        lines.append(
            f"  {len(result.extra)} IP(s) estão bloqueados no pf mas o banco não tinha registro: "
            f"{', '.join(result.extra)} (provavelmente bloqueio manual — não removido automaticamente)"
        )
    return "\n".join(lines)
