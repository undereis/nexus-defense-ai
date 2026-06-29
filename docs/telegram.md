# Telegram — notificação + controle do NOC (Fase 8)

O Telegram tem dois sentidos:

- **Saída (outbound):** a Nexus envia notificações ao grupo (bloqueio de
  inadimplente, queda de equipamento, etc.). Precisa só de token + chat_id.
- **Entrada (bidirecional, inbound):** o operador comanda o NOC pelo grupo
  (`/status`, `/block c1`, `/devices`...). O endpoint `api/server.py`
  `/telegram/webhook` recebe os updates, valida origem e roteia ao agente.
  Precisa que o Telegram **alcance a API por HTTPS público**.

Toda a operação está no script `scripts/telegram_smoke.py` (lê do `.env`; o
token **nunca** vai na linha de comando nem no chat).

## 1. Credenciais (uma vez)

1. **Bot:** `@BotFather` → `/newbot` → copie o **token**.
2. **Grupo:** crie/escolha um grupo, **adicione o bot** e mande 1 mensagem lá.
3. **.env:** preencha apenas o token (o `TELEGRAM_WEBHOOK_SECRET` já vem gerado):
   ```
   TELEGRAM_BOT_TOKEN=123456:ABC...
   TELEGRAM_CHAT_ID=            # descoberto no passo 2 abaixo
   TELEGRAM_WEBHOOK_SECRET=...  # já preenchido
   ```

## 2. Descobrir o chat_id (automático)

```
venv/bin/python scripts/telegram_smoke.py --discover-chat-id --save
```
Grava `TELEGRAM_CHAT_ID` no `.env`. (Se vier vazio: mande uma msg no grupo e
repita; e remova o webhook antes — `getUpdates` fica vazio com webhook ativo.)

## 3. Testar o ENVIO (outbound)

```
venv/bin/python scripts/telegram_smoke.py
```
Faz diagnóstico (getMe + getWebhookInfo) e **manda uma mensagem de teste**.
✅ Funcionou se a mensagem aparece no grupo.

## 4. Testar o BIDIRECIONAL (inbound)

Precisa expor a API por HTTPS. Com **ngrok**:

```
# terminal 1 — API
venv/bin/uvicorn api.server:app --host 0.0.0.0 --port 8000

# terminal 2 — túnel HTTPS
ngrok http 8000

# terminal 3 — registra o webhook na URL do ngrok (automático)
venv/bin/python scripts/telegram_smoke.py --webhook-from-ngrok
```

Depois, **mande `/status` no grupo** → o bot responde com o painel NOC.

## 5. Como saber se está respondendo

```
venv/bin/python scripts/telegram_smoke.py        # ou, no chat da Nexus: "telegram_status"
```
O campo decisivo é o **último erro de entrega** do `getWebhookInfo`:

| Saída | Significado |
|---|---|
| `sem erros — saudável ✅` | bidirecional recebendo |
| `⚠ ÚLTIMO ERRO DE ENTREGA: ...` | Telegram não alcança a API (túnel caiu / URL / secret) |
| `NÃO registrado` | só outbound; falta o passo 4 |

## Notas

- **Privacy mode:** por padrão o bot em grupo só recebe mensagens iniciadas por
  `/`. Use `/status`, `/block c1` (o código tira a barra e o `@bot`). Para texto
  livre, BotFather → `/setprivacy` → Disable.
- **Só o grupo autorizado** comanda: qualquer outro chat é ignorado e
  registrado como `telegram_unauthorized`.
- **Segurança:** o `.env` (com token + secret) nunca é commitado; ações de alto
  risco continuam passando pelo gate de `tools/risk.py`, qualquer que seja o
  canal.
- Remover o webhook: `scripts/telegram_smoke.py --delete-webhook`.
