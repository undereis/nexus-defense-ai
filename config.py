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

# A cada quantos segundos a Nexus verifica se o firewall real ainda
# corresponde ao que o banco acha que está bloqueado (drift detection).
RECONCILE_POLL_INTERVAL = int(os.getenv("RECONCILE_POLL_INTERVAL", "300"))

SSH_USER = os.getenv("SSH_USER", "")
SSH_KEY_PATH = os.getenv("SSH_KEY_PATH", "")

API_TOKEN = os.getenv("NEXUS_API_TOKEN", "")

# Webhook genérico para notificações fora do terminal (Slack incoming
# webhook, Discord webhook, ou qualquer endpoint custom que aceite JSON
# via POST). Vazio = notificações ficam só no terminal, como sempre foi.
NOTIFY_WEBHOOK_URL = os.getenv("NOTIFY_WEBHOOK_URL", "")
NOTIFY_WEBHOOK_FORMAT = os.getenv("NOTIFY_WEBHOOK_FORMAT", "slack")  # slack | discord | raw

# Signing secret do Slack app (Basic Information -> Signing Secret), usado
# para verificar que requisições em /slack/command vêm mesmo do Slack.
SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET", "")

# Bot User OAuth Token (xoxb-...) + canal de destino, para postar notificações
# direto via Slack Web API (chat.postMessage) em vez de um webhook genérico.
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN", "")
SLACK_CHANNEL_ID = os.getenv("SLACK_CHANNEL_ID", "")

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

# Padrões adicionais de enumeração de escalada de privilégio (read-only —
# nenhum altera estado do host). Separados do bloco acima só para destacar
# que são usados especificamente por tools/privesc.py.
SSH_ALLOWED_PATTERNS += [
    r"^sudo -l$",
    r"^id$",
    r"^find / -perm -4000 -type f 2>/dev/null$",
    r"^getcap -r / 2>/dev/null$",
    r"^cat /etc/crontab$",
    r"^ls -la /etc/cron\.d/?$",
    r"^env$",
]

# Exploração ativa (Metasploit) é a capacidade de maior impacto da Nexus —
# pode causar crash/instabilidade real até em alvos autorizados. Desativada
# por padrão; precisa ser ligada deliberadamente uma vez no .env. Depois de
# ligada, a Nexus roda módulos sem pedir confirmação extra por execução.
ALLOW_ACTIVE_EXPLOITATION = os.getenv("ALLOW_ACTIVE_EXPLOITATION", "false").lower() == "true"
MSF_TIMEOUT_SECONDS = int(os.getenv("MSF_TIMEOUT_SECONDS", "180"))

# Diretório onde a Nexus pode ler/escrever arquivos de hash e wordlists para
# cracking de senha e amostras para análise de malware — nunca fora dele.
WORKDIR = BASE_DIR / "workdir"
HASHCAT_TIMEOUT_SECONDS = int(os.getenv("HASHCAT_TIMEOUT_SECONDS", "300"))
JOHN_TIMEOUT_SECONDS = int(os.getenv("JOHN_TIMEOUT_SECONDS", "300"))

# Engenharia social (pretexting/phishing simulado) é a única capacidade que
# manipula PESSOAS reais, não infraestrutura — desativada por padrão, exige
# habilitação deliberada. Mesmo habilitada, a Nexus só GERA conteúdo (texto);
# nunca envia e-mail, SMS ou liga para ninguém — isso é sempre manual, feito
# por você, depois de revisar o conteúdo gerado.
ALLOW_SOCIAL_ENGINEERING = os.getenv("ALLOW_SOCIAL_ENGINEERING", "false").lower() == "true"

# Hydra (brute force de credenciais) e SQLMap (injeção SQL automatizada)
# são ações ativas contra um serviço/alvo ao vivo — podem gerar bloqueio
# de conta, alertas de IDS, ou tráfego pesado mesmo em alvo autorizado.
# Reaproveitam o mesmo toggle do Metasploit por serem da mesma categoria
# de risco (ação ofensiva ativa, não só leitura/scan passivo).
HYDRA_TIMEOUT_SECONDS = int(os.getenv("HYDRA_TIMEOUT_SECONDS", "300"))
SQLMAP_TIMEOUT_SECONDS = int(os.getenv("SQLMAP_TIMEOUT_SECONDS", "300"))

# A cada quantos segundos a Nexus ancora um checkpoint do estado da trilha
# de auditoria fora do banco local (via notificação), para detectar
# truncamento (remoção de eventos do final da cadeia de hash).
AUDIT_CHECKPOINT_INTERVAL = int(os.getenv("AUDIT_CHECKPOINT_INTERVAL", "1800"))

# Honeypot: porta-armadilha que não serve nenhum propósito real — qualquer
# conexão é evidência direta de varredura, isolada automaticamente sem
# depender de threshold ou de ALLOW_ACTIVE_EXPLOITATION (bloquear IP já é
# uma capacidade "core"). Desativado por padrão: abrir uma porta de rede
# é uma decisão deliberada.
HONEYPOT_ENABLED = os.getenv("HONEYPOT_ENABLED", "false").lower() == "true"
HONEYPOT_PORT = int(os.getenv("HONEYPOT_PORT", "2222"))
HONEYPOT_BANNER = os.getenv("HONEYPOT_BANNER", "SSH-2.0-OpenSSH_7.4\r\n")
