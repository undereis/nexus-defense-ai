import os
from pathlib import Path
from dotenv import load_dotenv

from core import secrets as _secrets

load_dotenv()

# Segredos (tokens/senhas) são lidos via `_secrets.get_secret`: Keychain do macOS
# primeiro, com fallback total pro .env (fail-safe — ver core/secrets.py). Já
# valores não-secretos (hosts, portas, chat_ids, flags) seguem por `os.getenv`.
_secret = _secrets.get_secret

BASE_DIR = Path(__file__).resolve().parent

CREATOR_NAME = os.getenv("CREATOR_NAME", "Criador")
ANTHROPIC_API_KEY = _secret("ANTHROPIC_API_KEY")
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

API_TOKEN = _secret("NEXUS_API_TOKEN", "")

# Chave Fernet usada exclusivamente para criptografar, em repouso, usuário e
# senha observados nos honeypots. Deve morar no Keychain/.env e nunca no banco.
HONEYPOT_CREDENTIAL_KEY = _secret("HONEYPOT_CREDENTIAL_KEY", "")

# --- Governança / Control Plane ---
# MODO OPERACIONAL do backend (fonte da verdade da EXECUÇÃO): 'real' | 'lab' |
# 'replay'. O cliente Tauri consulta e reflete este modo efetivo, mas não decide
# a autorização. Em 'lab'/'replay' a policy engine NÃO deixa
# executar ação real que altere estado (só leitura/refresh). Um operador pode
# sobrescrever em runtime (gravado em system_state); este valor é só o default.
NEXUS_OPERATING_MODE = os.getenv("NEXUS_OPERATING_MODE", "lab").lower()

# Ator/role padrão quando não há sistema de usuários real (compatível com o
# token único atual): toda ação sem ator explícito é atribuída a 'local_admin'
# com papel 'admin' — mantém o comportamento atual, mas já auditável e pronto
# para evoluir para usuários reais depois.
DEFAULT_ACTOR = os.getenv("NEXUS_DEFAULT_ACTOR", "local_admin")
DEFAULT_ROLE = os.getenv("NEXUS_DEFAULT_ROLE", "admin")

# RBAC por token na API REST (opcional). CSV de "papel:token" — ex.:
# "noc_operator:tkn_noc,auditor:tkn_aud". O NEXUS_API_TOKEN principal é SEMPRE
# admin; tokens listados aqui mapeiam para papéis com menos permissão
# (noc_operator/soc_analyst/auditor/readonly), permitindo permissões
# diferenciadas sem um sistema de usuários. Vazio = só o token admin. As ações
# REST resolvem o papel pelo token e o passam ao Control Plane. NUNCA commitar.
NEXUS_ROLE_TOKENS = _secret("NEXUS_ROLE_TOKENS", "")

# Exigir ativo AUTORIZADO no inventário (asset_registry) para ações sensíveis.
# false (padrão) = compatível com hoje: alvos que não estão no inventário são
# permitidos, mas AUDITADOS como "fora do inventário" (e as travas de segurança
# duras — infra própria crítica, loopback, reservado — sempre negam). true =
# endurece: só ativos explicitamente cadastrados e no escopo passam.
REQUIRE_ASSET_AUTHORIZATION = os.getenv("REQUIRE_ASSET_AUTHORIZATION", "false").lower() == "true"

# Auto-incidente: abre um incidente automaticamente em sinais inequívocos de
# ataque (ex.: hit em honeypot). Idempotente (reaproveita o incidente ativo do
# mesmo IP/tipo, só anota) e fail-safe. false (padrão) = não abre sozinho — o
# operador abre via open_incident. Ligar é uma decisão deliberada de ruído.
AUTO_INCIDENT_ENABLED = os.getenv("AUTO_INCIDENT_ENABLED", "false").lower() == "true"

# Assinatura HMAC opcional dos eventos de auditoria (Prioridade 7). Vazio =
# desligado (só a hash chain atual). Quando definido, a assinatura é gravada num
# canal LATERAL (não altera _compute_entry_hash nem invalida eventos antigos).
# Implementação de assinatura é etapa futura — ver docs/control_plane.md.
AUDIT_HMAC_SECRET = _secret("AUDIT_HMAC_SECRET", "")

# Webhook genérico para notificações fora do terminal (Slack incoming
# webhook, Discord webhook, ou qualquer endpoint custom que aceite JSON
# via POST). Vazio = notificações ficam só no terminal, como sempre foi.
NOTIFY_WEBHOOK_URL = os.getenv("NOTIFY_WEBHOOK_URL", "")
NOTIFY_WEBHOOK_FORMAT = os.getenv("NOTIFY_WEBHOOK_FORMAT", "slack")  # slack | discord | raw

# Signing secret do Slack app (Basic Information -> Signing Secret), usado
# para verificar que requisições em /slack/command vêm mesmo do Slack.
SLACK_SIGNING_SECRET = _secret("SLACK_SIGNING_SECRET", "")

# Feeds externos de threat intelligence (todos com tier gratuito). Vazio =
# a correlação correspondente é pulada, sem quebrar nada — igual ao padrão
# de NOTIFY_WEBHOOK_URL acima.
ABUSEIPDB_API_KEY = _secret("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = _secret("VIRUSTOTAL_API_KEY", "")
SHODAN_API_KEY = _secret("SHODAN_API_KEY", "")

# Reporta automaticamente ao AbuseIPDB todo IP que a Nexus confirma
# isolar (contamina a reputação global do atacante, sem precisar pedir).
# Só tem efeito se ABUSEIPDB_API_KEY estiver configurada.
AUTO_REPORT_ABUSEIPDB = os.getenv("AUTO_REPORT_ABUSEIPDB", "false").lower() == "true"

# Bot User OAuth Token (xoxb-...) + canal de destino, para postar notificações
# direto via Slack Web API (chat.postMessage) em vez de um webhook genérico.
SLACK_BOT_TOKEN = _secret("SLACK_BOT_TOKEN", "")
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

# DPI (Suricata): interface a capturar (vazio = não inicia automaticamente,
# só via tool explícita) e diretório onde o eve.json (log de alertas) fica.
DPI_INTERFACE = os.getenv("DPI_INTERFACE", "")
DPI_LOG_DIR = BASE_DIR / "workdir" / "dpi"

# BGP FlowSpec (RFC 5575): caminho do pipe de comando do ExaBGP (o BGP
# speaker que de fato envia os anúncios para a sessão com o upstream).
# Vazio = nenhum anúncio real é possível, só construção/validação de
# regra — é o estado esperado até a sessão BGP de produção existir.
EXABGP_API_PIPE = os.getenv("EXABGP_API_PIPE", "")

# A cada quantas horas os feeds globais de threat intel (Spamhaus DROP,
# Feodo Tracker, Emerging Threats) são atualizados.
THREAT_FEED_REFRESH_INTERVAL_HOURS = float(os.getenv("THREAT_FEED_REFRESH_INTERVAL_HOURS", "1"))

# Honeytokens: URL base PÚBLICA (alcançável de fora, ex: domínio/IP da
# Xfiber) usada no callback embutido em arquivos-isca — quando alguém
# abre o arquivo isca em qualquer lugar do mundo e o link "telefona pra
# casa", a Nexus precisa estar alcançável nesse endereço. Vazio = a
# tool avisa que precisa ser configurado antes de plantar arquivos.
CANARY_BASE_URL = os.getenv("CANARY_BASE_URL", "")
CANARY_LISTENER_PORT = int(os.getenv("CANARY_LISTENER_PORT", "8090"))

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

# Lista de "service:port" para iniciar automaticamente quando HONEYPOT_ENABLED.
# Padrão: só SSH na porta HONEYPOT_PORT. Para múltiplos serviços simultâneos,
# defina ex: HONEYPOT_SERVICES=ssh:2222,ftp:2121,http:8081
HONEYPOT_SERVICES = os.getenv("HONEYPOT_SERVICES", f"ssh:{HONEYPOT_PORT}")

# A cada quantos segundos o watchdog verifica se os honeypots configurados
# ainda estão rodando, e reinicia os que caíram.
WATCHDOG_INTERVAL = int(os.getenv("WATCHDOG_INTERVAL", "60"))

# A cada quantos segundos varremos ações de alto risco pendentes (gate de
# confirmação) e marcamos como expiradas as que passaram do prazo sem
# confirmação, notificando o criador fora do chat.
RISK_SWEEP_INTERVAL = int(os.getenv("RISK_SWEEP_INTERVAL", "60"))

# A cada quantas horas a Nexus gera e envia um resumo executivo do período
# (eventos, ataques, capturas de honeypot, estado do firewall) via notify.
REPORT_INTERVAL_HOURS = float(os.getenv("REPORT_INTERVAL_HOURS", "24"))

# Mikrotik RouterOS (ex: RB750) — acesso via API nativa (librouteros).
# Porta 8728 = sem TLS (só rede local/confiável). Porta 8729 = TLS, exigida
# para qualquer acesso pela internet, nunca mande credenciais em texto puro
# por fora da LAN.
MIKROTIK_HOST = os.getenv("MIKROTIK_HOST", "")
MIKROTIK_USER = os.getenv("MIKROTIK_USER", "")
MIKROTIK_PASSWORD = _secret("MIKROTIK_PASSWORD", "")
MIKROTIK_PORT = int(os.getenv("MIKROTIK_PORT", "8728"))
MIKROTIK_USE_TLS = os.getenv("MIKROTIK_USE_TLS", "false").lower() == "true"

# Timeout de conexão/comando com o Mikrotik. Sem isso, um roteador
# inacessível (cabo desconectado, firewall dropando pacote em vez de
# rejeitar) pode travar a thread chamando a tool por minutos, em vez de
# falhar rápido com uma mensagem clara.
MIKROTIK_TIMEOUT_SECONDS = int(os.getenv("MIKROTIK_TIMEOUT_SECONDS", "10"))

# Nível máximo que os playbooks executam AUTOMATICAMENTE, sem confirmação
# humana. 0 = desativado (só avalia e sugere, nunca age); 1 = só throttle;
# 2 = throttle + isolamento local; 4 = inclui reporte global (AbuseIPDB).
# NOTA CRÍTICA: Nível 3 (BGP FlowSpec) NUNCA executa automaticamente —
# esta barreira é programática e não pode ser contornada por esta config.
PLAYBOOK_AUTO_LEVEL = int(os.getenv("PLAYBOOK_AUTO_LEVEL", "0"))

# Habilita o bloqueio de ASN inteiro (todos os prefixos IP de uma
# organização). Blast radius altíssimo — pode bloquear tráfego legítimo
# do mesmo provedor. Desativado por padrão; habilitar é deliberado.
# Mesmo habilitado, SEMPRE passa pelo gate de confirmação (risk.py).
ALLOW_ASN_BLOCK = os.getenv("ALLOW_ASN_BLOCK", "false").lower() == "true"

# Intervalo em segundos para o loop de inventário automático de ativos.
# Escaneia os blocos IP próprios registrados e detecta novos devices ou
# mudanças de configuração. 3600 = a cada 1 hora. 0 = desativado.
ASSET_INVENTORY_SCAN_INTERVAL = int(os.getenv("ASSET_INVENTORY_SCAN_INTERVAL", "3600"))

# Modo de scan do inventário: 'passive' (só ping, descobre hosts ativos)
# ou 'light' (ping + top 100 portas TCP, detecta serviços). 'passive' é
# mais rápido e menos intrusivo; 'light' gera mais informação de auditoria.
ASSET_INVENTORY_SCAN_MODE = os.getenv("ASSET_INVENTORY_SCAN_MODE", "passive")

# Monitoramento dos DNS servers (resolvers .90/.91/.92). Intervalo em segundos
# do loop que faz health check + auditoria de portas + validade de certificado.
# 0 (padrão) = desativado; os servers precisam ser cadastrados primeiro com
# register_dns_server (ou via DNS_SERVERS abaixo) antes de ligar o loop.
DNS_MONITOR_INTERVAL = int(os.getenv("DNS_MONITOR_INTERVAL", "0"))

# Lista de IPs de DNS servers para cadastrar automaticamente no boot, separados
# por vírgula (ex.: "192.168.0.90,192.168.0.91,192.168.0.92"). Vazio = só os
# cadastrados manualmente via register_dns_server.
DNS_SERVERS = os.getenv("DNS_SERVERS", "")

# Domínio resolvido em cada health check para medir resposta/latência do
# resolver. Use um domínio sempre resolvível e neutro.
DNS_PROBE_DOMAIN = os.getenv("DNS_PROBE_DOMAIN", "example.com")

# Avisa quando o certificado de DoT (853) / DoH (443) estiver a menos de N
# dias de expirar. Cert vencido derruba DNS-over-TLS/HTTPS silenciosamente.
DNS_CERT_WARN_DAYS = int(os.getenv("DNS_CERT_WARN_DAYS", "30"))

# BrbOS — SO de servidor DNS da BrByte que roda nos resolvers da Xfiber.
# Enquanto tools/dns_monitor.py vê o resolver POR FORA (dig/porta/cert), a
# integração BrbOS dá visão POR DENTRO via API REST (mesma porta da interface
# web, padrão 8080): estatísticas de consultas, RPZ (bloqueio de domínio),
# rate limit e ACL. Sem credenciais, as tools de BrbOS avisam "não
# configurado" em vez de quebrar — mesmo padrão de mikrotik/threat_feeds.
BRBOS_HOST = os.getenv("BRBOS_HOST", "")
BRBOS_PORT = int(os.getenv("BRBOS_PORT", "8080"))
BRBOS_USER = os.getenv("BRBOS_USER", "")
BRBOS_PASSWORD = _secret("BRBOS_PASSWORD", "")
BRBOS_USE_TLS = os.getenv("BRBOS_USE_TLS", "false").lower() == "true"

# Habilita ESCRITA no BrbOS (bloqueio de domínio via RPZ). Desativado por
# padrão; habilitar é deliberado. Mesmo habilitado, todo bloqueio passa pelo
# gate de confirmação fora de banda (tools/risk.py) — igual ASN block.
# Leitura (estatísticas, listar RPZ/rate limit) não depende deste toggle.
ALLOW_BRBOS_BLOCK = os.getenv("ALLOW_BRBOS_BLOCK", "false").lower() == "true"

# Domínios da PRÓPRIA infraestrutura que a Nexus NUNCA pode bloquear/sinkholar
# (bloquear o próprio domínio derruba a rede inteira). Sufixos separados por
# vírgula, ex.: "xfiber.com.br,xfiber.local". Defesa em profundidade além do
# gate de confirmação — fortemente recomendado preencher.
BRBOS_PROTECTED_DOMAINS = os.getenv("BRBOS_PROTECTED_DOMAINS", "")

# --- Sandbox de malware (Fase 6, item 1) ---
# Detonação DINÂMICA de amostra é o que há de mais perigoso no projeto: roda
# código malicioso de verdade. Por isso vem com DUAS travas independentes,
# ambas obrigatórias, e o código se RECUSA a detonar se qualquer uma faltar:
#
#   1. ALLOW_MALWARE_DETONATION=true  — liga a capacidade (off por padrão).
#   2. MALWARE_SANDBOX_LAB_TOKEN=<algo> — prova de que o ambiente é um lab
#      isolado e descartável (host sacrificial com snapshot + egress
#      controlado). Em produção/dev este valor fica VAZIO e a detonação é
#      recusada — nunca detonar fora de lab (mesma regra do incidente do DNS).
#
# A análise ESTÁTICA e a extração de IOC não dependem destes toggles (não
# executam nada). Só a detonação dinâmica é gated.
ALLOW_MALWARE_DETONATION = os.getenv("ALLOW_MALWARE_DETONATION", "false").lower() == "true"
MALWARE_SANDBOX_LAB_TOKEN = _secret("MALWARE_SANDBOX_LAB_TOKEN", "")
# Backend de detonação (ex.: "cape" para CAPEv2). Vazio = nenhum wirado ainda
# (fase 2, exige lab). Mesmo com os dois toggles acima, sem backend a
# detonação retorna "nenhum backend configurado" em vez de rodar algo.
MALWARE_SANDBOX_BACKEND = os.getenv("MALWARE_SANDBOX_BACKEND", "")
MALWARE_SANDBOX_TIMEOUT_SECONDS = int(os.getenv("MALWARE_SANDBOX_TIMEOUT_SECONDS", "120"))

# --- Auto-ajuste de thresholds (Fase 7, item 4) ---
# O MAIS sensível de segurança: afrouxar um threshold (subir o z-score) reduz
# falsos positivos, mas pode CEGAR a detecção de ataques reais. Por isso o
# ajuste é SEMPRE bounded (piso/teto fixos no código de tools/threshold_tuning,
# passo limitado) e o operador fica no loop. Off por padrão: sem ele, a Nexus
# só PROPÕE ajustes — aplicar exige confirmação explícita do operador
# (confirm=True). Este toggle só serve para um futuro loop autônomo aplicar
# dentro dos limites; nesta versão nenhum loop aplica sozinho.
ALLOW_THRESHOLD_AUTOTUNE = os.getenv("ALLOW_THRESHOLD_AUTOTUNE", "false").lower() == "true"

# --- Operação de ISP / NOC (Fase 8): inadimplência + monitoramento ---
# Bloqueio de inadimplentes: liga o loop diário que bloqueia assinantes em
# atraso e reativa quem pagou. Off por padrão (opt-in para o subsistema
# iniciar); uma vez ligado, age automaticamente no horário — mas SEMPRE
# limitado pelo cap de segurança abaixo.
SUBSCRIBER_BILLING_ENABLED = os.getenv("SUBSCRIBER_BILLING_ENABLED", "false").lower() == "true"

# Hora do dia (0-23) em que o ciclo de cobrança roda. Dias mínimos de atraso
# para considerar um assinante inadimplente (= DIAS_PARA_BLOQUEIO do spec).
SUBSCRIBER_BLOCK_HOUR = int(os.getenv("SUBSCRIBER_BLOCK_HOUR", "8"))
SUBSCRIBER_BLOCK_DAYS = int(os.getenv("SUBSCRIBER_BLOCK_DAYS", "5"))

# CAP DE SEGURANÇA (filosofia do _AUTO_CAP): um ciclo que tentaria bloquear
# MAIS que isto de uma vez NÃO bloqueia ninguém — só alerta. Protege contra
# um erro na fonte de cobrança derrubar a base inteira. Para um bloqueio
# massivo legítimo, suba este valor deliberadamente.
SUBSCRIBER_BLOCK_MAX_BATCH = int(os.getenv("SUBSCRIBER_BLOCK_MAX_BATCH", "50"))

# Fonte dos dados de inadimplência: 'local' (tabela subscribers no nexus.db,
# funciona já hoje) ou 'external' (adaptador para o sistema real de cobrança,
# ainda não wirado — retorna "não configurado").
BILLING_SOURCE = os.getenv("BILLING_SOURCE", "local")

# Monitoramento de equipamentos (Microkit/OLT/switch) por ping. Intervalo em
# segundos do loop. 0 (padrão) = desligado, igual DNS_MONITOR_INTERVAL — os
# equipamentos precisam ser cadastrados antes (add_monitored_device).
DEVICE_MONITOR_INTERVAL = int(os.getenv("DEVICE_MONITOR_INTERVAL", "0"))

# Telegram — canal de notificação adicional (aditivo ao Slack/webhook). Bot
# token (via @BotFather) + chat/grupo de destino. Vazio = Telegram desligado,
# notificações seguem pelo Slack/webhook como sempre. NUNCA commitar o token.
TELEGRAM_BOT_TOKEN = _secret("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# Secret token do webhook do Telegram (controle bidirecional — operar o NOC pelo
# grupo). É o valor passado em setWebhook(secret_token=...) e devolvido pelo
# Telegram no header X-Telegram-Bot-Api-Secret-Token de cada update; o endpoint
# /telegram/webhook recusa requisições que não batam. Vazio = webhook
# bidirecional DESLIGADO (Telegram fica só outbound). Gere um valor aleatório
# forte e NUNCA o commite. Defesa em profundidade junto da checagem de chat_id.
TELEGRAM_WEBHOOK_SECRET = _secret("TELEGRAM_WEBHOOK_SECRET", "")

# --- Integração SIEM (Frente I) ---
# Encaminha os eventos da trilha de auditoria a um SIEM externo, incremental.
# SIEM_MODE: 'off' (padrão) | 'elastic' (_bulk) | 'splunk' (HEC) | 'webhook'
# (POST de array JSON genérico). Off = nada é enviado. SIEM_URL é o endpoint
# completo; SIEM_TOKEN a credencial (API key do Elastic / token do HEC / Bearer
# do webhook). SIEM_INDEX só vale para o elastic. Leitura/escrita só de eventos
# já gravados — não muda nada na detecção.
SIEM_MODE = os.getenv("SIEM_MODE", "off")
SIEM_URL = os.getenv("SIEM_URL", "")
SIEM_TOKEN = _secret("SIEM_TOKEN", "")
SIEM_INDEX = os.getenv("SIEM_INDEX", "nexus-events")
SIEM_BATCH = int(os.getenv("SIEM_BATCH", "500"))
SIEM_FORWARD_INTERVAL = int(os.getenv("SIEM_FORWARD_INTERVAL", "60"))
# CP-SD Fase 6K: intervalo mínimo (segundos) entre reavaliações de
# "siem.forward_events" pelo Control Plane quando a última decisão foi
# DENY/DRY_RUN_ONLY e o estado (modo operacional + actor + role) não mudou —
# evita reauditar a MESMA decisão a cada SIEM_FORWARD_INTERVAL, o que gravaria
# um `control_plane_decision` novo por ciclo indefinidamente (achado da Fase
# 6I/6J: cursor preso + auditoria da própria tentativa nunca sai da fila).
# 1800s (30min) reduz o ruído em ~48x frente ao intervalo padrão de 60s,
# mantendo um heartbeat de auditoria periódico (nunca cooldown infinito).
SIEM_REAUDIT_COOLDOWN_SECONDS = int(os.getenv("SIEM_REAUDIT_COOLDOWN_SECONDS", "1800"))
