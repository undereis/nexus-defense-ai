"""Camada de decisão determinística para ameaças de rede.

Separa "detecção" (contagem de conexões, já feito em DdosDetector) de
"decisão": ameaças muito acima do normal (severas) podem ser isoladas
na hora, sem esperar uma chamada de LLM — reduz latência de resposta e
custo de API. Ameaças moderadas continuam sendo avaliadas pelo agente,
que tem mais contexto e julgamento para decidir.
"""

from collections import Counter


def classify_threats(
    counts: Counter, threshold: int, severe_multiplier: float
) -> tuple[list[str], list[str]]:
    """Divide os IPs suspeitos (>= threshold) em duas listas:
    - severos: contagem >= threshold * severe_multiplier (ação automática)
    - moderados: entre threshold e o limite severo (decisão do agente)

    Se severe_multiplier <= 0, a classificação automática fica desativada
    e todo IP suspeito volta como moderado (comportamento padrão atual)."""
    severe: list[str] = []
    moderate: list[str] = []

    for ip, count in counts.items():
        if count < threshold:
            continue
        if severe_multiplier > 0 and count >= threshold * severe_multiplier:
            severe.append(ip)
        else:
            moderate.append(ip)

    return severe, moderate
