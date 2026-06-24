import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent

CREATOR_NAME = os.getenv("CREATOR_NAME", "Criador")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
MODEL_NAME = os.getenv("NEXUS_MODEL", "claude-sonnet-4-6")

DB_PATH = BASE_DIR / "database" / "nexus.db"

CONNECTIONS_PER_IP_THRESHOLD = 80
MONITOR_WINDOW_SECONDS = 10
MONITOR_POLL_INTERVAL = 5
ALERT_COOLDOWN_SECONDS = 300

# Multiplicador acima do threshold para isolar um IP automaticamente, sem
# esperar decisão do LLM (reduz latência e custo em ataques óbvios). 0 (padrão)
# desativa: todo IP suspeito continua passando pelo agente, como sempre foi.
AUTO_ISOLATE_MULTIPLIER = float(os.getenv("AUTO_ISOLATE_MULTIPLIER", "0"))

PF_ANCHOR_NAME = "nexus_defense"

# A cada quantos segundos o loop de auditoria proativa verifica se algum
# ativo autorizado já está "devido" para reauditoria (não é o intervalo
# de scan em si, que é por host — ver authorize_asset_for_monitoring).
PROACTIVE_AUDIT_POLL_INTERVAL = int(os.getenv("PROACTIVE_AUDIT_POLL_INTERVAL", "600"))

SSH_USER = os.getenv("SSH_USER", "")
SSH_KEY_PATH = os.getenv("SSH_KEY_PATH", "")

API_TOKEN = os.getenv("NEXUS_API_TOKEN", "")

# Allowlist de comandos remotos via SSH. Apenas comandos de diagnóstico
# read-only por padrão — nada que altere estado do host remoto. Para liberar
# mais, defina SSH_EXTRA_ALLOWED_PATTERNS no .env com regexes separados por "|".
SSH_ALLOWED_PATTERNS = [
    r"^docker ps( -a)?$",
    r"^docker (logs|inspect) [\w.-]+$",
    r"^systemctl status [\w@.-]+$",
    r"^service [\w@.-]+ status$",
    r"^uptime$",
    r"^df -h$",
    r"^free -h$",
    r"^whoami$",
    r"^uname -a$",
    r"^ps aux$",
    r"^netstat -tulpn$",
    r"^ss -tulpn$",
    r"^cat /etc/os-release$",
    r"^tail -n \d+ [\w./-]+$",
]
if os.getenv("SSH_EXTRA_ALLOWED_PATTERNS"):
    SSH_ALLOWED_PATTERNS += os.getenv("SSH_EXTRA_ALLOWED_PATTERNS").split("|")
