"""Modo operacional do BACKEND — fonte da verdade da EXECUÇÃO.

real | lab | replay. Independente do modo VISUAL do cliente Tauri (esse é só
localStorage do cliente e não trafega até aqui). Default vem de
config.NEXUS_OPERATING_MODE; um operador pode sobrescrever em runtime (gravado
na tabela system_state). A policy engine consulta isto para nunca deixar uma
ação real que altere estado rodar em lab/replay.

Módulo folha (sem dependência de outros módulos de core) para evitar ciclos.
"""

import config
from database.db import get_system_state, set_system_state

VALID_MODES: tuple[str, ...] = ("real", "lab", "replay")
_KEY = "operating_mode"


def get_operating_mode() -> str:
    val = (get_system_state(_KEY, "") or "").strip().lower()
    if val in VALID_MODES:
        return val
    default = (getattr(config, "NEXUS_OPERATING_MODE", "real") or "real").lower()
    return default if default in VALID_MODES else "real"


def set_operating_mode(mode: str) -> str:
    mode = (mode or "").strip().lower()
    if mode not in VALID_MODES:
        raise ValueError(f"Modo inválido: {mode!r}. Use um de {VALID_MODES}.")
    set_system_state(_KEY, mode)
    return mode


def allows_real_state_change() -> bool:
    """True só no modo 'real'. Em 'lab'/'replay', ações que ALTERAM ESTADO real
    não executam (leitura/refresh continuam permitidas)."""
    return get_operating_mode() == "real"
