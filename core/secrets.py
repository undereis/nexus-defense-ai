"""Leitura de segredos com backend de Keychain do macOS + fallback .env (Fase 1).

Objetivo: tirar os segredos (tokens de API, senhas) do `.env` em CLARO, guardando-os
no Keychain do macOS (login keychain), sem perder compatibilidade — se um segredo
não estiver no Keychain, cai no `os.getenv` (.env) exatamente como antes.

Design (regras invioláveis):
- **Keychain-first, fallback env**: se o item existe no Keychain, ele é a fonte da
  verdade (é pra onde o segredo migra); se não existe, usa o valor do ambiente/.env.
- **Fail-safe**: keyring ausente, backend indisponível, keychain travado ou QUALQUER
  erro de acesso -> cai silenciosamente no `os.getenv`. NUNCA levanta, NUNCA quebra o
  boot. (A API sobe como LaunchAgent — não pode travar num prompt de keychain.)
- **Nunca loga o valor**. `get_secret` devolve a string crua; quem loga passa pela
  redaction (`core/redaction`). Este módulo protege o armazenamento EM REPOUSO; a
  redaction protege a trilha de auditoria. Camadas complementares.
- **Hermético em teste**: sob pytest o backend cai para `env` por padrão (não toca o
  Keychain real do usuário). Override explícito via `NEXUS_SECRETS_BACKEND`.

A ESCRITA de segredos no Keychain (migração) é feita pelo operador via
`scripts/nexus_secrets.py` — o agente/LLM só tem acesso de LEITURA de STATUS
(presença + origem, nunca o valor). Não importa `config` (evita ciclo: `config`
importa este módulo).
"""

from __future__ import annotations

import os
import sys

# Nome do "service" no Keychain (agrupa todos os itens do Nexus).
SERVICE = "nexus-defense-ai"

# Nomes das VARIÁVEIS DE AMBIENTE que são segredo de verdade e podem morar no
# Keychain — são os "account" names dos itens. Alinhado com
# `redaction.SECRET_CONFIG_VARS` (que usa os nomes de ATRIBUTO de config; aqui
# usamos os nomes de ENV, que é o que vai no .env e vira a conta no Keychain).
SECRET_ENV_NAMES: tuple[str, ...] = (
    "ANTHROPIC_API_KEY",
    "NEXUS_API_TOKEN",
    "NEXUS_ROLE_TOKENS",
    "AUDIT_HMAC_SECRET",
    "HONEYPOT_CREDENTIAL_KEY",
    "SLACK_SIGNING_SECRET",
    "SLACK_BOT_TOKEN",
    "ABUSEIPDB_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "SHODAN_API_KEY",
    "MIKROTIK_PASSWORD",
    "BRBOS_PASSWORD",
    "MALWARE_SANDBOX_LAB_TOKEN",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_WEBHOOK_SECRET",
    "SIEM_TOKEN",
)

# Cache manual do módulo keyring: `[modulo_ou_None]`. Lista (e não valor direto)
# para distinguir "ainda não resolvido" de "resolvido como None", e permitir
# reset em teste via `reset_cache()`.
_KR_CACHE: list = []


def reset_cache() -> None:
    """Zera o cache do backend (para testes que trocam o ambiente)."""
    _KR_CACHE.clear()


def _keyring():
    """Módulo `keyring` se importável e com um backend real utilizável, senão
    None. Cacheado. Nunca levanta."""
    if _KR_CACHE:
        return _KR_CACHE[0]
    mod = None
    try:
        import keyring as _kr

        # Sanity: precisa haver um backend de fato (não o fail/null backend).
        backend = _kr.get_keyring()
        name = backend.__class__.__name__.lower()
        if "fail" in name or "null" in name:
            mod = None
        else:
            mod = _kr
    except Exception:
        mod = None
    _KR_CACHE.append(mod)
    return mod


def _under_pytest() -> bool:
    return "pytest" in sys.modules


def resolve_backend() -> str:
    """Backend ativo agora: `'keychain'` | `'env'`.

    Explícito por `NEXUS_SECRETS_BACKEND` (`auto` | `keychain` | `env`); em `auto`
    usa keychain só se disponível E fora de teste (hermético)."""
    choice = os.getenv("NEXUS_SECRETS_BACKEND", "auto").strip().lower()
    if choice == "env":
        return "env"
    if choice == "keychain":
        return "keychain" if _keyring() is not None else "env"
    # auto
    if _under_pytest():
        return "env"
    return "keychain" if _keyring() is not None else "env"


def keychain_available() -> bool:
    """True se há um backend de Keychain real utilizável."""
    return _keyring() is not None


def _keychain_get(name: str) -> str | None:
    """Lê um item do Keychain. None se ausente OU em qualquer erro (fail-safe)."""
    kr = _keyring()
    if kr is None:
        return None
    try:
        return kr.get_password(SERVICE, name)
    except Exception:
        return None


def get_secret(name: str, default: str = "") -> str:
    """Valor do segredo `name`: Keychain-first, fallback `os.getenv`, senão
    `default`. Nunca levanta."""
    try:
        if resolve_backend() == "keychain":
            v = _keychain_get(name)
            if v:  # só usa o Keychain se houver valor NÃO-vazio
                return v
    except Exception:
        pass  # fail-safe -> env
    return os.getenv(name, default)


def set_secret(name: str, value: str) -> bool:
    """Grava/atualiza um segredo no Keychain. True em sucesso. Não levanta.
    (Uso: operador migrando do .env — ver `scripts/nexus_secrets.py`.)"""
    kr = _keyring()
    if kr is None:
        return False
    try:
        kr.set_password(SERVICE, name, value)
        return True
    except Exception:
        return False


def delete_secret(name: str) -> bool:
    """Remove um segredo do Keychain. True se removido; False se ausente/erro."""
    kr = _keyring()
    if kr is None:
        return False
    try:
        kr.delete_password(SERVICE, name)
        return True
    except Exception:
        return False


def secret_source(name: str) -> str:
    """Onde `name` está sendo resolvido AGORA, sem revelar o valor:
    `'keychain'` | `'env'` | `'ausente'`."""
    try:
        if resolve_backend() == "keychain" and _keychain_get(name):
            return "keychain"
    except Exception:
        pass
    return "env" if os.getenv(name) else "ausente"


def secret_status() -> list[dict]:
    """Status de cada segredo gerenciado: `name` + `source` + `present`. NUNCA o
    valor — só presença e origem. Para diagnóstico/selftest/tool read-only."""
    return [
        {"name": n, "source": secret_source(n), "present": bool(get_secret(n))}
        for n in SECRET_ENV_NAMES
    ]
