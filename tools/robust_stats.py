"""Estatística robusta para baseline anti-envenenamento (Fase 7, item 2).

A detecção por z-score clássico (média + desvio padrão) tem um ponto cego
explorável: um atacante que sobe o tráfego DEVAGAR, ao longo de dias, arrasta a
MÉDIA da baseline junto. Quando o ataque "de verdade" chega, a média já foi
envenenada e o desvio parece normal — a anomalia não dispara. É o clássico
"frog boiling" contra detecção estatística.

A mediana e o MAD (Median Absolute Deviation) resistem a isso: poucas amostras
envenenadas não movem a mediana. O z-score modificado usa mediana/MAD no lugar
de média/desvio:

    z_mod = 0.6745 * (x - mediana) / MAD

O 0.6745 reescala o MAD para ficar na mesma grandeza do desvio padrão de uma
distribuição normal — então o mesmo threshold (ex.: 3.0) significa a mesma
coisa nos dois detectores.

Uso na Nexus: roda EM PARALELO ao z-score clássico. Se os dois discordam
(clássico diz "normal", robusto diz "anomalia"), é sinal de que a média pode
ter sido arrastada — a própria divergência é um alerta de envenenamento.

Funções puras, sem I/O — fáceis de testar e reusar (global e por cliente).
"""

import statistics

# Constante de consistência: MAD * 1.4826 ≈ desvio padrão (normal). Seu
# recíproco 0.6745 entra no numerador do z modificado.
_MAD_SCALE = 0.6745


def median_mad(values: list[float]) -> tuple[float, float]:
    """Retorna (mediana, MAD) de uma amostra. MAD = mediana dos desvios
    absolutos em relação à mediana. Lista vazia → (0.0, 0.0)."""
    if not values:
        return 0.0, 0.0
    med = statistics.median(values)
    mad = statistics.median([abs(v - med) for v in values])
    return med, mad


def modified_z_score(value: float, median: float, mad: float) -> float:
    """z-score robusto de um valor dada a mediana/MAD da baseline.

    Quando MAD == 0 (baseline de variância nula/degenerada) NÃO usamos inf:
    devolvemos 0.0 e deixamos o detector clássico (desvio padrão) decidir
    aquele caso. Isso evita que o detector robusto gere falso positivo a partir
    de uma baseline sem dispersão — segue a regra de nunca tornar a detecção
    ruidosa sem motivo (o clássico já cobre variância nula)."""
    if mad == 0:
        return 0.0
    return _MAD_SCALE * (value - median) / mad


def robust_z(value: float, values: list[float]) -> float:
    """Atalho: z-score robusto de um valor contra uma amostra histórica."""
    med, mad = median_mad(values)
    return modified_z_score(value, med, mad)
