"""Redaction de segredos antes de logar / auditar / exportar (Prioridade 8).

Centraliza num só lugar:
- os NOMES de variáveis/campos sensíveis (token, senha, chave, secret...);
- o mascaramento de um valor de segredo (`mask_token`);
- a redaction de uma string livre (`redact`) — por padrão (Bearer, api_key=...,
  password=..., bot token do Telegram) E por valor exato dos segredos de fato
  configurados no .env (pega o token mesmo sem rótulo ao lado);
- a redaction de um dicionário de argumentos (`redact_kwargs`).

Regras de ouro:
- NUNCA levanta exceção — uma redaction com defeito jamais pode derrubar uma
  ação ou a gravação da auditoria. Em caso de erro, falha FECHADO (redige tudo).
- Nunca logar token, senha, chave privada ou secret em claro.

Keychain/Vault de verdade é etapa futura — ver docs/control_plane.md. Aqui
tratamos do mínimo profissional: não vazar segredo na trilha/saída.
"""

import re

# Nomes canônicos de campos sensíveis. Qualquer chave (de dict/dump) cujo nome
# contenha um destes (case-insensitive) é tratada como segredo e mascarada.
SENSITIVE_NAMES: tuple[str, ...] = (
    "token", "password", "passwd", "secret", "api_key", "apikey", "api-key",
    "private_key", "privatekey", "signing_secret", "webhook_secret", "lab_token",
    "bot_token", "credential", "passphrase", "authorization", "bearer",
)

# Variáveis de config cujos VALORES são segredo real — redigidas por match exato
# onde quer que apareçam numa string (mesmo sem um rótulo "token=" ao lado).
SECRET_CONFIG_VARS: tuple[str, ...] = (
    "ANTHROPIC_API_KEY", "API_TOKEN", "SLACK_SIGNING_SECRET", "SLACK_BOT_TOKEN",
    "ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY", "SHODAN_API_KEY",
    "MIKROTIK_PASSWORD", "BRBOS_PASSWORD", "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_WEBHOOK_SECRET", "SIEM_TOKEN", "MALWARE_SANDBOX_LAB_TOKEN",
)

MASK = "***REDACTED***"

_KV_KEYS = (
    r"token|password|passwd|secret|api[_-]?key|signing[_-]?secret|"
    r"webhook[_-]?secret|bot[_-]?token|private[_-]?key|passphrase|credential|"
    r"community"
)

# Separador chave/valor: "="/":" (com espaço opcional dos dois lados) OU só
# espaço — cobre tanto "key=value"/"key: value" quanto sintaxe de CLI de rede
# (Cisco/Huawei/RouterOS), que é espaço-separada: "password MinhaSenha123",
# "snmp-server community public123". CP-SD Fase 4B microcorreção: comando cru
# de configure_network_device passa por isto antes de auditoria/summary/log.
_KV_SEP = r"(?:\s*[:=]\s*|\s+)"

# (padrão, substituição) — `re.sub` aceita string (com backrefs) ou callable.
_PATTERNS: list[tuple[re.Pattern, object]] = [
    # Authorization: Bearer xxxxx  /  bearer xxxxx (mínimo curto — não assumir
    # que um token de teste/lab "pequeno" é seguro só por ser curto).
    (re.compile(r"(?i)\b(bearer)\s+([A-Za-z0-9._\-]{2,})"), r"\1 " + MASK),
    # chave_sensivel = valor  /  chave_sensivel: valor  /  chave_sensivel valor
    (re.compile(rf"(?i)\b({_KV_KEYS}){_KV_SEP}(\"?)([^\s\"',;]+)(\"?)"),
     lambda m: f"{m.group(1)} {m.group(2)}{MASK}{m.group(4)}"),
    # Telegram bot token: 123456789:AAxxxxxxxx...
    (re.compile(r"\b\d{6,12}:[A-Za-z0-9_\-]{30,}"), MASK),
]


def _live_secret_values() -> list[str]:
    """Valores de segredo de fato configurados (lazy import de config para não
    criar ciclo e refletir mudanças em runtime)."""
    try:
        import config
    except Exception:
        return []
    vals: list[str] = []
    for name in SECRET_CONFIG_VARS:
        v = getattr(config, name, "")
        if isinstance(v, str) and len(v) >= 6:
            vals.append(v)
    return vals


def redact(text: object) -> str:
    """Devolve `text` com segredos mascarados. Não levanta: em erro, redige tudo."""
    if not text:
        return ""
    try:
        s = str(text)
        for secret in _live_secret_values():
            if secret and secret in s:
                s = s.replace(secret, MASK)
        for pattern, repl in _PATTERNS:
            s = pattern.sub(repl, s)  # type: ignore[arg-type]
        return s
    except Exception:
        return MASK


def mask_token(value: object, keep: int = 2) -> str:
    """Mostra só os primeiros/últimos `keep` caracteres de um segredo curto."""
    if not value:
        return ""
    v = str(value)
    if len(v) <= keep * 2:
        return MASK
    return f"{v[:keep]}{'*' * 6}{v[-keep:]}"


def is_sensitive_name(name: object) -> bool:
    n = str(name).lower()
    return any(s in n for s in SENSITIVE_NAMES)


def redact_kwargs(data: object) -> object:
    """Redige um dicionário de argumentos: valores de chaves com nome sensível
    viram MASK; strings comuns passam por `redact`; recursivo em sub-dicts."""
    if not isinstance(data, dict):
        return redact(data) if isinstance(data, str) else data
    out: dict = {}
    for k, v in data.items():
        if is_sensitive_name(k):
            out[k] = MASK if v not in (None, "", 0) else v
        elif isinstance(v, dict):
            out[k] = redact_kwargs(v)
        elif isinstance(v, list):
            out[k] = [redact_kwargs(i) if isinstance(i, dict) else (redact(i) if isinstance(i, str) else i) for i in v]
        elif isinstance(v, str):
            out[k] = redact(v)
        else:
            out[k] = v
    return out
