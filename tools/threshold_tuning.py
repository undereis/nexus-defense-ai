"""Auto-ajuste de thresholds (Fase 7, item 4).

A Nexus aprende com os ERROS dos próprios alertas e recalibra os limites de
detecção sozinha — em vez de o operador ter que ficar ajustando z-score na mão.

Como aprende: o operador rotula um alerta como
  - 'fp'     (falso positivo: disparou e não era ataque)
  - 'tp'     (verdadeiro positivo: disparou e era ataque mesmo)
  - 'missed' (detecção perdida: era ataque e NÃO disparou)
Esses rótulos são a verdade-terreno. Excesso de 'fp' → o threshold está
sensível demais (muito ruído) → subir o z-score. Excesso de 'missed' → está
frouxo demais (cego) → baixar o z-score.

POR QUE ESTE É O ITEM MAIS SENSÍVEL DE SEGURANÇA:
  Subir o z-score reduz falsos positivos MAS pode CEGAR a detecção de ataques
  reais. Um auto-ajuste ingênuo que só persegue "menos alertas" converge para
  "não alerta nunca". Defesas embutidas, todas no código (não dependem de
  config que alguém possa afrouxar):

  1. TETO RÍGIDO (_Z_CEILING): o threshold NUNCA sobe acima dele, por mais
     falsos positivos que haja. É o anti-cegueira — o limite de quão surda a
     detecção pode ficar.
  2. PISO RÍGIDO (_Z_FLOOR): nunca fica absurdamente sensível.
  3. PASSO LIMITADO (_Z_STEP): cada ajuste move no máximo um passo pequeno —
     sem saltos bruscos.
  4. MÍNIMO DE EVIDÊNCIA (_MIN_FEEDBACK): não mexe em nada sem rótulos
     suficientes — não reage a um único alerta.
  5. OPERADOR NO LOOP: aplicar um ajuste exige confirmação explícita
     (confirm=True) OU o toggle config.ALLOW_THRESHOLD_AUTOTUNE (para um futuro
     loop autônomo). Por padrão a Nexus só PROPÕE; quem aplica é o operador.
  6. RE-CLAMP NA LEITURA: effective_threshold() re-aplica piso/teto toda vez
     que lê o valor — mesmo um valor gravado fora dos limites é corrigido.

Stateless quanto ao cálculo: a proposta é sempre derivada dos feedbacks
persistidos no momento, então reflete a evidência atual.

NÃO usa ML — é uma regra explicável (contagem de fp/tp/missed + passo bounded),
honesta sobre o que faz.
"""

from config import ALLOW_THRESHOLD_AUTOTUNE
from database.db import (
    delete_tuned_threshold,
    get_alert_feedback_counts,
    get_tuned_threshold,
    list_tuned_thresholds,
    record_alert_feedback,
    upsert_tuned_threshold,
)
from tools.anomaly import DEFAULT_Z_SCORE_THRESHOLD
from tools.client_baseline import DEFAULT_Z_THRESHOLD

# --- Limites rígidos do ajuste (hardcoded de propósito — segurança) ---
_Z_FLOOR = 1.5       # nunca mais sensível que isso
_Z_CEILING = 5.0     # ANTI-CEGUEIRA: nunca menos sensível que isso
_Z_STEP = 0.5        # passo máximo por ajuste
_MIN_FEEDBACK = 5    # rótulos mínimos antes de propor qualquer mudança
_FP_RATE_RAISE = 0.4    # fração de fp acima da qual considera subir (menos sensível)
_MISSED_RATE_LOWER = 0.4  # fração de missed acima da qual considera baixar (mais sensível)

LABELS = ("fp", "tp", "missed")

# Base default por tipo de alerta (o ponto de partida quando não há override).
_DEFAULT_BASE = {
    "global_anomaly": DEFAULT_Z_SCORE_THRESHOLD,
    "client_anomaly": DEFAULT_Z_THRESHOLD,
}


def _clamp_z(z: float) -> float:
    """Garante piso <= z <= teto. A trava anti-cegueira definitiva."""
    return max(_Z_FLOOR, min(_Z_CEILING, z))


def base_for(alert_type: str) -> float:
    """Threshold base (de partida) de um tipo de alerta."""
    return _DEFAULT_BASE.get(alert_type, DEFAULT_Z_SCORE_THRESHOLD)


def effective_threshold(alert_type: str, scope: str, base: float | None = None) -> float:
    """O threshold que a detecção deve realmente usar: o aprendido (re-clampado
    no piso/teto) se existir, senão o base. É por aqui que o ajuste do item 4
    entra na detecção — composto, p.ex., com o delta de risco do item 3."""
    if base is None:
        base = base_for(alert_type)
    row = get_tuned_threshold(alert_type, scope)
    if row is None:
        return base
    return _clamp_z(row[0])  # row[0] = threshold; re-clamp sempre, defesa em profundidade


def record_feedback(alert_type: str, scope: str, label: str,
                    z_score: float | None = None, note: str = "") -> str:
    """Registra o rótulo do operador sobre um alerta (fp/tp/missed)."""
    label = (label or "").strip().lower()
    if label not in LABELS:
        return f"Rótulo inválido: {label!r}. Use um de: {', '.join(LABELS)}."
    scope = scope or "global"
    record_alert_feedback(alert_type, scope, label, z_score, note)
    return (
        f"Feedback registrado: {alert_type}/{scope} = {label}"
        + (f" (z={z_score})" if z_score is not None else "")
        + ". Use propose_threshold_tuning para ver se já há evidência suficiente "
        "para recalibrar."
    )


def _counts(alert_type: str, scope: str) -> dict:
    rows = dict(get_alert_feedback_counts(alert_type, scope))
    fp = rows.get("fp", 0)
    tp = rows.get("tp", 0)
    missed = rows.get("missed", 0)
    return {"fp": fp, "tp": tp, "missed": missed, "total": fp + tp + missed}


def propose_adjustment(alert_type: str, scope: str, base: float | None = None) -> dict:
    """Calcula (sem aplicar) o ajuste sugerido a partir dos feedbacks.
    Retorna dict com current, proposed, direction, actionable, reason, counts."""
    if base is None:
        base = base_for(alert_type)
    current = effective_threshold(alert_type, scope, base)
    c = _counts(alert_type, scope)
    result = {
        "alert_type": alert_type,
        "scope": scope,
        "base": base,
        "current": current,
        "proposed": current,
        "direction": "manter",
        "actionable": False,
        "counts": c,
        "reason": "",
    }
    if c["total"] < _MIN_FEEDBACK:
        result["reason"] = (
            f"evidência insuficiente: {c['total']} rótulo(s) "
            f"(mínimo {_MIN_FEEDBACK} para recalibrar)."
        )
        return result

    fp_rate = c["fp"] / c["total"]
    missed_rate = c["missed"] / c["total"]

    if c["missed"] > c["fp"] and missed_rate >= _MISSED_RATE_LOWER:
        # Está cego demais: baixar o z-score (mais sensível).
        proposed = _clamp_z(current - _Z_STEP)
        direction = "baixar (mais sensível)"
        why = (
            f"{c['missed']} detecção(ões) perdida(s) vs {c['fp']} falso(s) "
            f"positivo(s): detecção frouxa demais."
        )
    elif c["fp"] > c["missed"] and fp_rate >= _FP_RATE_RAISE:
        # Ruído demais: subir o z-score (menos sensível) — mas nunca além do teto.
        proposed = _clamp_z(current + _Z_STEP)
        direction = "subir (menos sensível)"
        why = (
            f"{c['fp']} falso(s) positivo(s) vs {c['missed']} perdida(s): "
            f"detecção sensível demais (ruído)."
        )
    else:
        result["reason"] = (
            f"calibração estável: fp={c['fp']} tp={c['tp']} missed={c['missed']} "
            "— sem pressão clara para mudar."
        )
        return result

    if proposed == current:
        # Já encostou no piso/teto: a trava de segurança impede ir além.
        bound = "teto" if direction.startswith("subir") else "piso"
        result["reason"] = (
            f"{why} Porém já no {bound} de segurança ({current}) — "
            "ajuste bloqueado para não cegar/ensurdecer a detecção."
        )
        result["direction"] = direction
        return result

    result.update({
        "proposed": proposed,
        "direction": direction,
        "actionable": True,
        "reason": why,
    })
    return result


def apply_adjustment(alert_type: str, scope: str, confirm: bool = False,
                     base: float | None = None) -> str:
    """Aplica o ajuste proposto — APENAS com confirmação do operador
    (confirm=True) ou com config.ALLOW_THRESHOLD_AUTOTUNE ligado. O valor
    gravado é sempre clampado no piso/teto."""
    proposal = propose_adjustment(alert_type, scope, base)
    if not proposal["actionable"]:
        return f"Nada a aplicar para {alert_type}/{scope}: {proposal['reason']}"

    if not (confirm or ALLOW_THRESHOLD_AUTOTUNE):
        return (
            f"PROPOSTA (não aplicada) {alert_type}/{scope}: "
            f"{proposal['current']} → {proposal['proposed']} "
            f"[{proposal['direction']}]. Motivo: {proposal['reason']} "
            "Operador no loop: para aplicar, confirme (confirm=True) ou ligue "
            "ALLOW_THRESHOLD_AUTOTUNE. Subir o threshold reduz ruído mas pode "
            "cegar a detecção — por isso a confirmação."
        )

    new_value = _clamp_z(proposal["proposed"])
    c = proposal["counts"]
    upsert_tuned_threshold(
        alert_type, scope, new_value, proposal["base"],
        samples_at_tune=c["total"], reason=proposal["reason"],
    )
    how = "confirmado pelo operador" if confirm else "auto (ALLOW_THRESHOLD_AUTOTUNE)"
    return (
        f"Threshold de {alert_type}/{scope} ajustado: "
        f"{proposal['current']} → {new_value} [{proposal['direction']}] ({how}). "
        f"Limites de segurança: piso {_Z_FLOOR}, teto {_Z_CEILING}."
    )


def reset_threshold(alert_type: str, scope: str) -> str:
    """Remove o override aprendido, revertendo ao base."""
    if delete_tuned_threshold(alert_type, scope):
        return (
            f"Threshold de {alert_type}/{scope} revertido ao base "
            f"({base_for(alert_type)})."
        )
    return f"Nenhum threshold aprendido para {alert_type}/{scope} (já estava no base)."


def describe_tuning(alert_type: str, scope: str = "global") -> str:
    """Relatório textual do estado de calibração de um (alert_type, scope)."""
    proposal = propose_adjustment(alert_type, scope)
    c = proposal["counts"]
    lines = [
        f"Calibração de {alert_type}/{scope}:",
        f"  Threshold atual: {proposal['current']} (base {proposal['base']}; "
        f"piso {_Z_FLOOR}, teto {_Z_CEILING})",
        f"  Feedback: {c['fp']} falso(s) positivo(s), {c['tp']} verdadeiro(s), "
        f"{c['missed']} perdida(s) — {c['total']} no total",
    ]
    if proposal["actionable"]:
        lines.append(
            f"  SUGESTÃO: {proposal['current']} → {proposal['proposed']} "
            f"[{proposal['direction']}] — {proposal['reason']}"
        )
        lines.append(
            "  (não aplicada — requer confirm=True ou ALLOW_THRESHOLD_AUTOTUNE)"
        )
    else:
        lines.append(f"  Sem ajuste: {proposal['reason']}")
    return "\n".join(lines)


def tuning_overview() -> str:
    """Resumo de todos os thresholds aprendidos atualmente."""
    rows = list_tuned_thresholds()
    if not rows:
        return (
            "Nenhum threshold aprendido ainda — todos no base. Use "
            "record_alert_feedback para rotular alertas e propose_threshold_tuning "
            "para ver sugestões."
        )
    lines = [f"Thresholds aprendidos ({len(rows)}):"]
    for alert_type, scope, threshold, base, n, reason, updated in rows:
        eff = _clamp_z(threshold)
        flag = "" if eff == threshold else f" (re-clampado de {threshold})"
        lines.append(
            f"  {alert_type}/{scope}: {eff}{flag} (base {base}, "
            f"{n} amostra(s) — {reason or 'sem motivo'}; {updated[:16]})"
        )
    return "\n".join(lines)
