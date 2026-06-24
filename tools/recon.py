"""Ferramentas de reconhecimento e auditoria de segurança ofensiva.

Usadas pela Nexus para avaliar a postura de segurança de domínios/IPs que
o criador autorizou explicitamente a testar (pentest em ativos próprios ou
com autorização). Nada aqui deve ser usado contra terceiros sem permissão.
"""

import re
import shutil
import subprocess
import time

import requests

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*$"
)

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def _validate_target(target: str) -> str:
    target = target.strip()
    if not _HOSTNAME_RE.match(target):
        raise ValueError(f"Target inválido: {target}")
    return target


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Comando excedeu {timeout}s: {' '.join(cmd)}")


def nmap_scan(target: str, ports: str = "") -> str:
    """Escaneia portas e serviços de um host com nmap (-sV). Use apenas em
    ativos próprios ou com autorização explícita do dono do domínio/IP."""
    target = _validate_target(target)
    if not shutil.which("nmap"):
        return "nmap não está instalado. Rode: brew install nmap"
    cmd = ["nmap", "-sV", target]
    if ports:
        cmd = ["nmap", "-sV", "-p", ports, target]
    result = _run(cmd, timeout=120)
    if result.returncode != 0:
        return f"Falha no nmap: {result.stderr.strip()}"
    return result.stdout.strip()


def nikto_scan(target: str) -> str:
    """Roda o Nikto contra um servidor web para achar arquivos perigosos,
    configurações inseguras e software desatualizado. Pode levar alguns
    minutos. Use apenas em ativos autorizados."""
    target = _validate_target(target)
    if not shutil.which("nikto"):
        return "nikto não está instalado. Rode: brew install nikto"
    result = _run(["nikto", "-h", target, "-ask", "no"], timeout=240)
    output = (result.stdout or "") + (result.stderr or "")
    return output.strip() or "Nikto não retornou saída."


def check_security_headers(target: str) -> str:
    """Verifica os headers HTTP de segurança de um site (HSTS, CSP,
    X-Frame-Options etc.), de forma equivalente a securityheaders.com,
    mas rodando localmente sem depender de serviço externo."""
    target = _validate_target(target)
    url = target if target.startswith("http") else f"https://{target}"
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
    except requests.RequestException as exc:
        return f"Falha ao conectar em {url}: {exc}"

    present = []
    missing = []
    for header in SECURITY_HEADERS:
        if header in resp.headers:
            present.append(f"{header}: {resp.headers[header]}")
        else:
            missing.append(header)

    lines = [f"Headers de segurança para {url} (status {resp.status_code}):", ""]
    lines.append("Presentes:")
    lines.extend(f"  - {h}" for h in present) if present else lines.append("  (nenhum)")
    lines.append("Ausentes:")
    lines.extend(f"  - {h}" for h in missing) if missing else lines.append("  (nenhum)")
    return "\n".join(lines)


def check_ssl_labs(target: str) -> str:
    """Consulta a API pública do SSL Labs (Qualys) para avaliar a
    configuração TLS/SSL de um host. Scans novos podem levar 1-2 minutos;
    se ainda estiver processando, chame de novo em seguida."""
    target = _validate_target(target)
    api = "https://api.ssllabs.com/api/v3/analyze"
    params = {"host": target, "fromCache": "on", "maxAge": "24", "all": "done"}

    for _ in range(6):
        try:
            resp = requests.get(api, params=params, timeout=15)
            data = resp.json()
        except requests.RequestException as exc:
            return f"Falha ao consultar SSL Labs: {exc}"

        status = data.get("status")
        if status == "READY":
            endpoints = data.get("endpoints", [])
            lines = [f"SSL Labs — {target}: {status}"]
            for ep in endpoints:
                lines.append(f"  IP {ep.get('ipAddress')}: grade {ep.get('grade', '?')}")
            return "\n".join(lines)
        if status == "ERROR":
            return f"SSL Labs retornou erro: {data.get('statusMessage')}"
        time.sleep(15)

    return "SSL Labs ainda processando o scan. Pergunte de novo em um minuto."


def zap_baseline_scan(target: str) -> str:
    """Roda um scan baseline do OWASP ZAP (passivo, rápido) contra uma URL,
    se o ZAP estiver instalado localmente (zap-baseline.py ou zap.sh)."""
    target = _validate_target(target)
    url = target if target.startswith("http") else f"https://{target}"

    if shutil.which("zap-baseline.py"):
        result = _run(["zap-baseline.py", "-t", url], timeout=300)
        return (result.stdout or result.stderr).strip()

    return (
        "OWASP ZAP não está instalado neste sistema. Instale com:\n"
        "  brew install --cask owasp-zap\n"
        "Depois disso, abra o ZAP e use 'Automated Scan' apontando para a URL, "
        "ou instale o zap-baseline.py para eu poder rodar via linha de comando."
    )
