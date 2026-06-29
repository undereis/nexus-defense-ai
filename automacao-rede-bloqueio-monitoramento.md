# Automação de Rede — Bloqueio de Inadimplentes + Monitoramento Microkit

## Visão Geral

Sistema automatizado para:
1. **Bloquear clientes inadimplentes** via SSH no roteador/switch
2. **Monitorar quedas do Microkit** (OLT/ONU/roteador) e notificar administrador
3. **Notificar via Telegram** (bot em grupo) e e-mail

---

## Arquitetura Geral

```
┌─────────────────────────────────────────────────────────────┐
│                     BACKOFFICE (PHPMaker)                   │
│                  Banco de dados de clientes                 │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    API Node.js                              │
│                                                             │
│  GET  /clientes/inadimplentes      → lista quem bloquear   │
│  GET  /clientes/reativados         → lista quem desbloquear │
│  POST /clientes/:id/status         → atualiza status        │
│  GET  /mikrotik/dispositivos       → lista os Microkits     │
│  POST /alertas/queda               → registra queda         │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│               ORQUESTRADOR Python                           │
│                                                             │
│  scheduler.py     → agenda as tarefas (APScheduler)        │
│  bloqueio.py      → lógica de bloqueio/desbloqueio         │
│  monitoramento.py → ping/SNMP nos Microkits                │
│  notificador.py   → Telegram + E-mail                      │
└──────┬──────────────────────┬───────────────────────────────┘
       │                      │
       ▼                      ▼
┌─────────────┐     ┌──────────────────────┐
│  SSH        │     │  NOTIFICAÇÕES        │
│  Roteadores │     │  - Bot Telegram      │
│  Switches   │     │  - E-mail SMTP       │
│  (Netmiko)  │     └──────────────────────┘
└─────────────┘
```

---

## Módulo 1 — API Node.js

### Estrutura

```
api/
├── src/
│   ├── routes/
│   │   ├── clientes.js       # Endpoints de clientes
│   │   └── dispositivos.js   # Endpoints de Microkits
│   ├── services/
│   │   ├── clienteService.js # Regras de negócio
│   │   └── dispositivoService.js
│   ├── db/
│   │   └── connection.js     # Conexão com banco do PHPMaker
│   └── app.js
├── .env
└── package.json
```

### Endpoints principais

```javascript
// routes/clientes.js

const express = require('express');
const router  = express.Router();
const db      = require('../db/connection');

// Retorna clientes inadimplentes acima de X dias
router.get('/inadimplentes', async (req, res) => {
    const dias = req.query.dias ?? 5;
    const [rows] = await db.query(`
        SELECT 
            c.id,
            c.nome,
            c.ip_address,
            c.interface,
            c.dispositivo_id,
            f.vencimento,
            DATEDIFF(NOW(), f.vencimento) AS dias_atraso
        FROM clientes c
        JOIN faturas f ON f.cliente_id = c.id
        WHERE 
            f.status = 'pendente'
            AND DATEDIFF(NOW(), f.vencimento) >= ?
            AND c.status_conexao = 'ativo'
        ORDER BY dias_atraso DESC
    `, [dias]);
    res.json(rows);
});

// Retorna clientes que pagaram e devem ser reativados
router.get('/reativados', async (req, res) => {
    const [rows] = await db.query(`
        SELECT c.id, c.nome, c.ip_address, c.interface, c.dispositivo_id
        FROM clientes c
        WHERE c.status_conexao = 'bloqueado_inadimplencia'
          AND NOT EXISTS (
              SELECT 1 FROM faturas f
              WHERE f.cliente_id = c.id AND f.status = 'pendente'
          )
    `);
    res.json(rows);
});

// Atualiza status do cliente
router.post('/:id/status', async (req, res) => {
    const { status, motivo } = req.body;
    await db.query(
        'UPDATE clientes SET status_conexao = ?, updated_at = NOW() WHERE id = ?',
        [status, req.params.id]
    );
    await db.query(
        'INSERT INTO logs_automacao (cliente_id, acao, motivo, created_at) VALUES (?, ?, ?, NOW())',
        [req.params.id, status, motivo]
    );
    res.json({ success: true });
});

module.exports = router;
```

```javascript
// routes/dispositivos.js

router.get('/mikrotik', async (req, res) => {
    const [rows] = await db.query(`
        SELECT id, nome, ip, modelo, localizacao, status
        FROM dispositivos
        WHERE tipo = 'mikrotik'
    `);
    res.json(rows);
});

// Registra queda de dispositivo
router.post('/alertas/queda', async (req, res) => {
    const { dispositivo_id, ip, nome, motivo } = req.body;
    await db.query(
        `INSERT INTO alertas_rede 
         (dispositivo_id, ip, nome, motivo, status, created_at) 
         VALUES (?, ?, ?, ?, 'aberto', NOW())`,
        [dispositivo_id, ip, nome, motivo]
    );
    res.json({ success: true });
});
```

---

## Módulo 2 — Orquestrador Python

### Estrutura

```
automacao/
├── scheduler.py         # Agendamento das tarefas
├── bloqueio.py          # Bloqueio/desbloqueio via SSH
├── monitoramento.py     # Ping e SNMP nos Microkits
├── notificador.py       # Telegram + E-mail
├── api_client.py        # Comunicação com a API Node.js
├── config.py            # Configurações centralizadas
└── requirements.txt
```

### config.py

```python
import os
from dotenv import load_dotenv

load_dotenv()

# API
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:3000")
API_KEY      = os.getenv("API_KEY")

# Regra de negócio
DIAS_PARA_BLOQUEIO = int(os.getenv("DIAS_PARA_BLOQUEIO", 5))

# Telegram
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_GRUPO_ID  = os.getenv("TELEGRAM_GRUPO_ID")

# E-mail
SMTP_HOST     = os.getenv("SMTP_HOST")
SMTP_PORT     = int(os.getenv("SMTP_PORT", 587))
SMTP_USER     = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
EMAIL_DESTINO = os.getenv("EMAIL_DESTINO")

# SSH padrão dos equipamentos
SSH_USER     = os.getenv("SSH_USER")
SSH_PASSWORD = os.getenv("SSH_PASSWORD")
```

### api_client.py

```python
import httpx
from config import API_BASE_URL, API_KEY

headers = {"Authorization": f"Bearer {API_KEY}"}

async def get_inadimplentes(dias: int) -> list:
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{API_BASE_URL}/clientes/inadimplentes",
                             params={"dias": dias}, headers=headers)
        r.raise_for_status()
        return r.json()

async def get_reativados() -> list:
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{API_BASE_URL}/clientes/reativados", headers=headers)
        r.raise_for_status()
        return r.json()

async def atualizar_status(cliente_id: int, status: str, motivo: str):
    async with httpx.AsyncClient() as client:
        await client.post(f"{API_BASE_URL}/clientes/{cliente_id}/status",
                          json={"status": status, "motivo": motivo},
                          headers=headers)

async def get_dispositivos_mikrotik() -> list:
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{API_BASE_URL}/mikrotik", headers=headers)
        r.raise_for_status()
        return r.json()

async def registrar_queda(dispositivo: dict, motivo: str):
    async with httpx.AsyncClient() as client:
        await client.post(f"{API_BASE_URL}/alertas/queda",
                          json={**dispositivo, "motivo": motivo},
                          headers=headers)
```

### bloqueio.py

```python
from netmiko import ConnectHandler
from config import SSH_USER, SSH_PASSWORD
import logging

logger = logging.getLogger(__name__)

def _conectar(ip: str) -> ConnectHandler:
    return ConnectHandler(
        device_type="mikrotik_routeros",
        host=ip,
        username=SSH_USER,
        password=SSH_PASSWORD,
        timeout=10
    )

def bloquear_cliente(ip_cliente: str, ip_dispositivo: str, interface: str) -> bool:
    """Bloqueia o IP do cliente no roteador via SSH."""
    try:
        conn = _conectar(ip_dispositivo)
        # Adiciona regra de bloqueio no firewall do MikroTik
        conn.send_command(
            f'/ip firewall filter add chain=forward '
            f'src-address={ip_cliente} action=drop '
            f'comment="BLOQUEIO_INADIMPLENTE_{ip_cliente}"'
        )
        conn.disconnect()
        logger.info(f"Cliente {ip_cliente} bloqueado em {ip_dispositivo}")
        return True
    except Exception as e:
        logger.error(f"Falha ao bloquear {ip_cliente} em {ip_dispositivo}: {e}")
        return False

def desbloquear_cliente(ip_cliente: str, ip_dispositivo: str) -> bool:
    """Remove regra de bloqueio do cliente."""
    try:
        conn = _conectar(ip_dispositivo)
        # Remove regra pelo comentário
        output = conn.send_command(
            f'/ip firewall filter print where '
            f'comment="BLOQUEIO_INADIMPLENTE_{ip_cliente}"'
        )
        if ".id" in output:
            conn.send_command(
                f'/ip firewall filter remove [find '
                f'comment="BLOQUEIO_INADIMPLENTE_{ip_cliente}"]'
            )
        conn.disconnect()
        logger.info(f"Cliente {ip_cliente} desbloqueado em {ip_dispositivo}")
        return True
    except Exception as e:
        logger.error(f"Falha ao desbloquear {ip_cliente} em {ip_dispositivo}: {e}")
        return False
```

### monitoramento.py

```python
import asyncio
import subprocess
from config import SSH_USER, SSH_PASSWORD
from api_client import get_dispositivos_mikrotik, registrar_queda
from notificador import notificar_queda
import logging

logger = logging.getLogger(__name__)

# Controle de estado para não notificar repetidamente
dispositivos_caidos: set = set()

def ping(ip: str) -> bool:
    """Verifica se o dispositivo responde ao ping."""
    result = subprocess.run(
        ["ping", "-c", "2", "-W", "2", ip],
        capture_output=True
    )
    return result.returncode == 0

async def verificar_dispositivos():
    """Verifica todos os Microkits e notifica se algum caiu."""
    dispositivos = await get_dispositivos_mikrotik()

    for d in dispositivos:
        ip   = d["ip"]
        nome = d["nome"]

        esta_online = ping(ip)

        if not esta_online and ip not in dispositivos_caidos:
            # Caiu agora — registra e notifica
            dispositivos_caidos.add(ip)
            logger.warning(f"Microkit CAIU: {nome} ({ip})")
            await registrar_queda(d, motivo="Sem resposta ao ping")
            await notificar_queda(nome, ip, d.get("localizacao", ""))

        elif esta_online and ip in dispositivos_caidos:
            # Voltou — remove do set e notifica normalização
            dispositivos_caidos.discard(ip)
            logger.info(f"Microkit VOLTOU: {nome} ({ip})")
            await notificar_normalizacao(nome, ip)
```

### notificador.py

```python
import httpx
import smtplib
from email.mime.text import MIMEText
from config import (
    TELEGRAM_BOT_TOKEN, TELEGRAM_GRUPO_ID,
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, EMAIL_DESTINO
)
import logging

logger = logging.getLogger(__name__)

# --- Telegram ---

async def _telegram(mensagem: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    async with httpx.AsyncClient() as client:
        await client.post(url, json={
            "chat_id": TELEGRAM_GRUPO_ID,
            "text": mensagem,
            "parse_mode": "Markdown"
        })

# --- E-mail ---

def _email(assunto: str, corpo: str):
    msg = MIMEText(corpo, "html")
    msg["Subject"] = assunto
    msg["From"]    = SMTP_USER
    msg["To"]      = EMAIL_DESTINO
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)

# --- Notificações específicas ---

async def notificar_queda(nome: str, ip: str, localizacao: str):
    msg_telegram = (
        f"🔴 *MICROKIT CAIU*\n"
        f"📍 *{nome}* — `{ip}`\n"
        f"🗺️ Local: {localizacao}\n"
        f"⏰ Verificar imediatamente!"
    )
    corpo_email = f"""
        <h2 style="color:red">⚠️ Microkit Offline</h2>
        <p><b>Dispositivo:</b> {nome}</p>
        <p><b>IP:</b> {ip}</p>
        <p><b>Local:</b> {localizacao}</p>
        <p>Verifique o equipamento imediatamente.</p>
    """
    await _telegram(msg_telegram)
    _email(f"[ALERTA] Microkit Offline: {nome}", corpo_email)

async def notificar_normalizacao(nome: str, ip: str):
    msg = f"🟢 *MICROKIT VOLTOU*\n📍 *{nome}* — `{ip}`\nConexão restabelecida."
    await _telegram(msg)

async def notificar_bloqueios(bloqueados: list, falhas: list):
    if not bloqueados and not falhas:
        return
    linhas = ["📵 *Bloqueios Realizados*\n"]
    for c in bloqueados:
        linhas.append(f"✅ {c['nome']} — `{c['ip_address']}`")
    for c in falhas:
        linhas.append(f"❌ FALHA: {c['nome']} — `{c['ip_address']}`")
    await _telegram("\n".join(linhas))
```

### scheduler.py

```python
import asyncio
import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from api_client import get_inadimplentes, get_reativados, atualizar_status
from bloqueio import bloquear_cliente, desbloquear_cliente
from monitoramento import verificar_dispositivos
from notificador import notificar_bloqueios
from config import DIAS_PARA_BLOQUEIO

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

async def tarefa_bloqueio():
    """Bloqueia inadimplentes e desbloqueia quem pagou."""
    logger.info("Iniciando tarefa de bloqueio...")

    # Bloqueios
    inadimplentes = await get_inadimplentes(DIAS_PARA_BLOQUEIO)
    bloqueados, falhas = [], []

    for cliente in inadimplentes:
        ok = bloquear_cliente(
            ip_cliente=cliente["ip_address"],
            ip_dispositivo=cliente["dispositivo_ip"],
            interface=cliente["interface"]
        )
        if ok:
            await atualizar_status(cliente["id"], "bloqueado_inadimplencia",
                                   f"{cliente['dias_atraso']} dias em atraso")
            bloqueados.append(cliente)
        else:
            falhas.append(cliente)

    # Desbloqueios
    reativados = await get_reativados()
    for cliente in reativados:
        ok = desbloquear_cliente(
            ip_cliente=cliente["ip_address"],
            ip_dispositivo=cliente["dispositivo_ip"]
        )
        if ok:
            await atualizar_status(cliente["id"], "ativo", "Pagamento confirmado")

    await notificar_bloqueios(bloqueados, falhas)
    logger.info(f"Bloqueios: {len(bloqueados)} ok, {len(falhas)} falhas. "
                f"Reativados: {len(reativados)}")

async def tarefa_monitoramento():
    """Verifica se todos os Microkits estão online."""
    await verificar_dispositivos()

def main():
    scheduler = AsyncIOScheduler()

    # Bloqueio: roda todo dia às 08:00
    scheduler.add_job(tarefa_bloqueio, "cron", hour=8, minute=0)

    # Monitoramento: roda a cada 2 minutos
    scheduler.add_job(tarefa_monitoramento, "interval", minutes=2)

    scheduler.start()
    logger.info("Agendador iniciado. Aguardando tarefas...")

    try:
        asyncio.get_event_loop().run_forever()
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()

if __name__ == "__main__":
    main()
```

---

## Variáveis de Ambiente (.env)

```env
# API
API_BASE_URL=http://localhost:3000
API_KEY=seu_token_seguro_aqui

# Regra de negócio
DIAS_PARA_BLOQUEIO=5

# SSH dos equipamentos
SSH_USER=admin
SSH_PASSWORD=senha_dos_equipamentos

# Telegram
TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
TELEGRAM_GRUPO_ID=-100123456789

# E-mail
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=sistema@suaempresa.com
SMTP_PASSWORD=senha_app
EMAIL_DESTINO=admin@suaempresa.com
```

---

## requirements.txt

```
netmiko==4.3.0
apscheduler==3.10.4
httpx==0.27.0
python-dotenv==1.0.1
```

---

## Tabelas no Banco (PHPMaker)

```sql
-- Tabela de dispositivos Microkit
CREATE TABLE dispositivos (
    id          INT PRIMARY KEY AUTO_INCREMENT,
    nome        VARCHAR(100),
    ip          VARCHAR(15),
    modelo      VARCHAR(100),
    localizacao VARCHAR(200),
    tipo        ENUM('mikrotik','olt','switch') DEFAULT 'mikrotik',
    status      ENUM('online','offline') DEFAULT 'online'
);

-- Log de ações automáticas
CREATE TABLE logs_automacao (
    id          INT PRIMARY KEY AUTO_INCREMENT,
    cliente_id  INT,
    acao        VARCHAR(50),
    motivo      TEXT,
    created_at  DATETIME
);

-- Alertas de queda
CREATE TABLE alertas_rede (
    id              INT PRIMARY KEY AUTO_INCREMENT,
    dispositivo_id  INT,
    ip              VARCHAR(15),
    nome            VARCHAR(100),
    motivo          TEXT,
    status          ENUM('aberto','resolvido') DEFAULT 'aberto',
    created_at      DATETIME,
    resolved_at     DATETIME NULL
);
```

---

## Fluxo de Execução

```
08:00 diário
    ↓
API Node.js → busca inadimplentes com X+ dias de atraso
    ↓
Python → bloqueia via SSH no MikroTik de cada cliente
    ↓
API Node.js → atualiza status do cliente
    ↓
Telegram → notifica resumo dos bloqueios

A cada 2 minutos
    ↓
Python → ping em todos os Microkits cadastrados
    ↓
Microkit não responde?
    ├── SIM → API registra queda + Telegram + E-mail ao admin
    └── NÃO → continua monitorando

Microkit voltou?
    └── Telegram notifica normalização
```

---

## Etapas de Construção Sugeridas

| Etapa | O que fazer | Prioridade |
|---|---|---|
| 1 | Criar tabelas no banco do PHPMaker | Alta |
| 2 | Construir API Node.js com endpoints de clientes | Alta |
| 3 | Testar bloqueio SSH manual em um MikroTik | Alta |
| 4 | Implementar `bloqueio.py` e testar isolado | Alta |
| 5 | Criar bot no Telegram e testar notificação | Média |
| 6 | Implementar `monitoramento.py` com ping | Média |
| 7 | Juntar tudo no `scheduler.py` | Média |
| 8 | Deploy em servidor Linux com systemd | Baixa |
| 9 | Adicionar endpoints de dispositivos na API | Baixa |

---

# Revisão e Correções (integração Nexus — Fase 8)

> **Status:** este spec foi **implementado como a Fase 8 do Nexus Defense AI**
> (2026-06-29), NÃO como o stack Node.js + Python separado descrito acima. O
> Nexus já tinha ~80% das peças, todas auditadas — subir um stack paralelo
> criaria uma segunda fonte de verdade, uma segunda trilha de auditoria e uma
> segunda integração MikroTik. O design abaixo é o que de fato está rodando.

## Por que integrar em vez de construir do zero

| Componente do spec | Substituído por (no Nexus) |
|---|---|
| API Node.js + MySQL/PHPMaker | `tools/billing.py` + adaptador `BillingSource` (local agora; externo depois) + tabelas no `nexus.db` |
| `bloqueio.py` (netmiko/SSH) | `tools/mikrotik.block_subscriber_ip/unblock_subscriber_ip` — **API nativa RouterOS** (librouteros), não SSH; TLS-capable; já auditada |
| `monitoramento.py` (ping + `set` em memória) | `tools/device_monitor.py` — estado **persistido no banco** (sobrevive a restart) |
| `notificador.py` (Telegram + SMTP) | `tools/telegram.py` ligado ao `tools/notify.py` (Slack/webhook já existentes). SMTP foi **descartado** — Telegram + Slack cobrem o caso |
| `scheduler.py` (APScheduler) | Threads de loop no `main.py` (`subscriber_billing_loop`, `device_monitor_loop`) |
| `dispositivos` / `logs_automacao` / `alertas_rede` | `monitored_devices` / `subscriber_actions` / `device_outages` |
| Senha SSH em `.env` | **Eliminada** — usa credencial RouterOS (`MIKROTIK_*`, porta 8729/TLS) |

## Bugs corrigidos do código de referência

1. **`scheduler.py` usava `cliente["dispositivo_ip"]`**, mas o endpoint
   `/inadimplentes` só devolvia `dispositivo_id` — `KeyError` em produção. No
   Nexus, o assinante carrega `device_host` (o MikroTik que o controla) e os
   campos vêm sempre do mesmo registro.
2. **`monitoramento.py` chamava `notificar_normalizacao` sem importá-la** —
   `NameError` na primeira recuperação de equipamento. No Nexus, a notificação
   de queda/recuperação é uma única função (`notify.send_notification`).
3. **`interface` era recebido e nunca usado** em `bloquear_cliente`. Removido
   do caminho de bloqueio (o bloqueio é por `src-address`, não por interface).
4. **Estado em memória (`dispositivos_caidos: set`)** — perdido a cada
   restart, gerando alerta duplicado de queda. Corrigido: estado vive em
   `monitored_devices.current_status`.

## Salvaguardas adicionadas (não existiam no spec)

- **CAP de lote (`SUBSCRIBER_BLOCK_MAX_BATCH`, padrão 50):** um ciclo que
  bloquearia mais que o cap de uma vez **não bloqueia ninguém** — só alerta.
  Protege contra um erro na fonte de cobrança derrubar a base inteira (mesma
  filosofia do `_AUTO_CAP` do playbook). O spec bloqueava tudo, sem limite.
- **Proteção de infraestrutura:** nunca bloqueia loopback nem IP crítico
  próprio (`_is_safe_to_block`, análogo de `honeypot._is_safe_to_isolate`).
- **Idempotência:** a régua do MikroTik dedupa pelo comentário
  `BLOQUEIO_INADIMPLENTE_<ip>`; o ciclo só olha assinantes no estado certo.
- **Auditoria:** todo bloqueio/desbloqueio entra na hash-chain de `events` +
  na tabela `subscriber_actions`.

## Como operar (no Nexus)

- **Toggles (`.env`):** `SUBSCRIBER_BILLING_ENABLED`, `SUBSCRIBER_BLOCK_HOUR`,
  `SUBSCRIBER_BLOCK_DAYS`, `SUBSCRIBER_BLOCK_MAX_BATCH`, `BILLING_SOURCE`,
  `DEVICE_MONITOR_INTERVAL`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`.
- **Tools do agente:** `add_subscriber`, `set_subscriber_invoice_status`,
  `list_delinquent_subscribers`, `run_billing_cycle_now(dry_run=True)`,
  `block_subscriber`/`unblock_subscriber`, `add_monitored_device`,
  `check_devices_now`, `list_device_outages`, `send_telegram_test`.
- **Fonte de cobrança real:** quando o sistema (PHPMaker/API) estiver
  acessível, implementar `ExternalBillingSource` em `tools/billing.py` e setar
  `BILLING_SOURCE=external` — o resto não muda.
