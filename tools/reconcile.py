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
            result = firewall.block_ip(ip, reason="Reaplicado por reconciliação (drift detectado)")
            if result.startswith("IP") and "sucesso" in result:
                reapplied.append(ip)
            else:
                errors[ip] = result

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
