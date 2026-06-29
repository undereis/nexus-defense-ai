# Nexus — Contrato da API REST (para clientes externos)

Arquitetura: o **motor fica em Python** (servidor Linux: agente + tools + DB +
monitor) e qualquer **interface visual é um cliente** que fala HTTP com esta
API — incluindo o cliente desktop de referência (Tauri + React) em
`clients/tauri/` e o dashboard web embutido (`/dashboard`).

Servir: `venv/bin/uvicorn api.server:app --host 0.0.0.0 --port 8000`
(em produção, atrás de HTTPS — nginx/caddy ou túnel).

## Autenticação

Header `Authorization: Bearer <NEXUS_API_TOKEN>` em todos os endpoints `/api/*`,
`/chat` e `/dashboard/data`. O token vem de `NEXUS_API_TOKEN` no `.env` (se
vazio, o servidor gera um temporário e o imprime no stdout ao subir). Sem token
ou token errado → `401`.

`/health` e `/dashboard` (a casca HTML) são públicos.

## Endpoints

### Saúde / visão geral
| Método | Rota | Auth | Resposta |
|---|---|---|---|
| GET | `/health` | não | `{"status":"ok"}` |
| GET | `/api/overview` | sim | objeto agregado (igual `/dashboard/data`): `subscribers`, `devices`, `open_outages`, `blocked_ips`, `events_24h`, `recent_events`, `honeypots`, `pending_actions`, `generated_at` |
| GET | `/api/health` | sim | `{"report": "<texto do autodiagnóstico>"}` |

### Consultas (read-only)
| Método | Rota | Params | Resposta |
|---|---|---|---|
| GET | `/api/subscribers` | — | `{"subscribers":[{id,name,ip,device_host,interface,status,invoice_status,days_overdue}]}` |
| GET | `/api/devices` | — | `{"devices":[{id,name,ip,model,location,type,enabled,status,last_change}]}` |
| GET | `/api/outages` | `status=aberto\|resolvido\|''` | `{"outages":[{device_id,ip,name,reason,status,opened_at,resolved_at}]}` |
| GET | `/api/events` | `hours=24` | `{"events":[{type,ip,detail,action,time}]}` (até 200 mais recentes) |

### Ações (POST)
| Método | Rota | Params | Resposta |
|---|---|---|---|
| POST | `/api/subscribers/{id}/block` | `reason=...` | `{"message":"OK c1 (203.0.113.5): ..."}` |
| POST | `/api/subscribers/{id}/unblock` | `reason=...` | `{"message":"OK c1 (...)"}` |
| POST | `/api/billing/run` | `dry_run=true` | `{"message":"..."}` (dry_run só lista; cap de segurança vale) |
| POST | `/api/devices/check` | — | `{"transitions":["DOWN d1 (10.0.0.1)", ...]}` |

> As ações reaproveitam a guarda e a auditoria dos módulos: bloqueio recusa IP
> de infraestrutura, é idempotente e fica na hash-chain. Ações de **alto risco**
> (exploração, ASN/BGP, RPZ) **não** estão nesta API — continuam só pelo agente,
> atrás do gate de `tools/risk.py`.

### Agente (linguagem natural)
| Método | Rota | Body | Resposta |
|---|---|---|---|
| POST | `/chat` | `{"message":"..."}` | `{"reply":"..."}` (passa pelo agente/LLM) |

Use `/chat` para perguntas livres e ações que pedem julgamento; use `/api/*`
para telas com botões e listas (rápido, determinístico, sem LLM).

## Exemplo (curl)
```bash
TOKEN=seu_token
BASE=http://127.0.0.1:8000
curl -s -H "Authorization: Bearer $TOKEN" $BASE/api/overview
curl -s -H "Authorization: Bearer $TOKEN" $BASE/api/subscribers
curl -s -X POST -H "Authorization: Bearer $TOKEN" "$BASE/api/billing/run?dry_run=true"
```

## Notas de segurança
- Sempre atrás de **HTTPS** fora da LAN (o token vai no header em texto).
- O token é o que protege as ações — trate como segredo; rotacione se vazar.
- CORS não está habilitado por padrão e **não precisa ser**: o cliente Tauri
  faz as requisições pelo plugin HTTP nativo (Rust), que não passa pela política
  de CORS do webview. Para um front web servido em outro domínio, aí sim seria
  preciso habilitar CORS explicitamente.
