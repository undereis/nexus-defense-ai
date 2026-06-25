"""Enumeração de vetores de escalada de privilégio em um host autorizado,
via SSH — só comandos read-only (mesmo princípio de linpeas/linEnum, mas
sem baixar/executar um script de terceiros no alvo). Reaproveita a
allowlist de comandos SSH já existente (tools/access.py); todas essas
checagens já estão liberadas em config.SSH_ALLOWED_PATTERNS."""

from tools import access

_CHECKS = [
    ("Usuário atual", "id"),
    ("Permissões sudo", "sudo -l"),
    ("Binários com SUID", "find / -perm -4000 -type f 2>/dev/null"),
    ("Capabilities especiais", "getcap -r / 2>/dev/null"),
    ("Crontab do sistema", "cat /etc/crontab"),
    ("Cron jobs em /etc/cron.d", "ls -la /etc/cron.d"),
    ("Variáveis de ambiente", "env"),
]


def enumerate_privesc(host: str, user: str = "") -> str:
    """Roda uma sequência de comandos de diagnóstico read-only via SSH para
    identificar vetores comuns de escalada de privilégio: sudo mal
    configurado, binários SUID, capabilities, cron jobs como root, etc."""
    lines = [f"Enumeração de escalada de privilégio em {host}:", ""]
    for label, command in _CHECKS:
        result = access.ssh_run_command(host, command, user)
        lines.append(f"## {label} (`{command}`)")
        lines.append(result.strip() or "(sem saída)")
        lines.append("")
    return "\n".join(lines)
