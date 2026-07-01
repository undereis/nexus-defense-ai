# Control Plane & Policy Engine — governança de ações sensíveis

> Primeira entrega das fundações de governança. O Nexus deixa de ser "uma IA com
> ferramentas" e passa a ser uma **plataforma de segurança governada**: ações
> sensíveis controladas, alvos autorizados, permissões por papel, aprovações e
> auditoria forte. Esta é a **base** — as fases seguintes estão em "Próximos
> passos".

## Arquitetura

```
Usuário / API / IA
  → ActionRequest (pedido estruturado)
  → Control Plane         core/control_plane.py
      → Policy Engine     core/policy_engine.py   (decisão determinística)
          → RBAC          core/rbac.py            (papel tem a permissão?)
          → Inventário    tools/asset_registry.py (ativo autorizado? trava de segurança?)
          → Modo          core/operating_mode.py  (real/lab/replay)
          → Risco/Toggle  config ALLOW_*          (capacidade ligada?)
      → Decisão: ALLOW | DENY | REQUIRE_APPROVAL | DRY_RUN_ONLY
      → Auditoria         database.db.log_event (hash chain) + redaction (core/redaction.py)
      → Aprovação humana  tools/risk.py (gate fora de banda — reaproveitado)
      → Executor da tool
  → ActionResult (auditado)
```

### Módulos

| Arquivo | Papel | Prioridade |
|---|---|---|
| `core/models.py` | `ActionRequest/ActionDecision/ActionResult/ActionRisk/ActionStatus/Decision` (folha) | 1 |
| `core/control_plane.py` | orquestra: avalia → audita → aprova/executa | 1 |
| `core/policy_engine.py` | `evaluate()` determinístico + `ACTION_CATALOG` | 2 |
| `tools/asset_registry.py` | inventário de ativos autorizados + `check_target()` | 3 |
| `core/rbac.py` | papéis e permissões | 4 |
| `tools/risk.py` (existente) | gate de aprovação fora de banda — **reaproveitado** | 5 |
| `core/operating_mode.py` | modo operacional do backend (real/lab/replay) | — |
| `core/redaction.py` | mascarar segredo antes de logar | 7/8 |

### Tabelas novas (SQLite, migração-segura — `CREATE TABLE IF NOT EXISTS`)

- **`asset_registry`** — ativos AUTORIZADOS para ação sensível: `asset_id`,
  `asset_type` (network/host/mikrotik/subscriber/server/sensor/honeypot/lab),
  `hostname/ip/cidr`, `owner`, `environment` (real/lab), `authorized_scope`,
  `valid_from/valid_until`, `notes`, `enabled`. Distinta de `authorized_assets`
  (agendamento de auditoria proativa) e de `assets` (descoberta por scan).
- **`system_state`** — chave/valor de runtime; guarda o modo operacional.

## Decisões da Policy Engine (ordem; DENY tem precedência)

1. **RBAC** — papel sem a permissão exigida → `DENY`.
2. **Segurança dura** — alvo é infra própria crítica / loopback / reservado →
   `DENY` (sempre, independente de config; mesma filosofia de `_is_safe_to_isolate`).
3. **Toggle** — capacidade exige `ALLOW_*` desligado → `DENY`.
4. **Engagement ref** — engenharia social sem `engagement_reference` → `DENY`.
5. **Inventário** — alvo não autorizado (modo estrito) → `DENY`.
6. **Modo** — em `lab`/`replay`, ação que altera estado real → `DRY_RUN_ONLY`.
7. **Aprovação** — risco alto/crítico (ou marcado) → `REQUIRE_APPROVAL` (via `risk.py`).
8. Caso contrário → `ALLOW`.

## Modo operacional — fonte da verdade

- **Backend** (`core/operating_mode`): `real | lab | replay`. Default
  `config.NEXUS_OPERATING_MODE` (`real`), override em runtime via `system_state`
  (tools `get_operating_mode`/`set_operating_mode`). **É o que governa a
  EXECUÇÃO.**
- **Cliente Tauri** (modo visual Real/Lab/Replay): é só `localStorage` do cliente,
  para honestidade visual — **não trafega** até o backend e **não** decide
  execução. São fontes da verdade SEPARADAS e propositalmente independentes.
  Sincronizá-las (ex.: cliente enviar um header de modo desejado, o backend
  decidir se aceita) é um passo futuro.

## Compatibilidade (nada quebra por padrão)

- Ator/role padrão: `local_admin`/`admin` (`config.DEFAULT_ACTOR/DEFAULT_ROLE`),
  compatível com o token único atual. Admin tem todas as permissões — mas ações
  de alto risco ainda passam por aprovação.
- Modo padrão: `real`.
- Inventário: `REQUIRE_ASSET_AUTHORIZATION=false` (padrão) → alvo fora do
  inventário é permitido porém **auditado** como "fora do inventário"; só as
  travas de segurança duras negam. `true` endurece (só ativos cadastrados passam).
- A trilha de auditoria (hash chain) **não foi alterada**: a redaction acontece
  ANTES do `log_event`, então o que entra na cadeia é o texto já redigido —
  eventos antigos continuam válidos e `_compute_entry_hash` não mudou.

## O que já passa pelo Control Plane (integração-vitrine)

| Ação | Onde | Caminho |
|---|---|---|
| **Isolar/bloquear IP** | `agents/nexus_agent.isolate_ip` | agente → control plane → `firewall.block_ip` |
| **Bloquear/desbloquear assinante** | `tools/noc_api.block_subscriber/unblock_subscriber` | **REST `/api/...` e cliente Tauri** → control plane → `billing` |
| **SSH remoto** (Fase 2) | `run_remote_command` | `request_action` (`ssh_command`, read-only — allowlist mantida) → `access.ssh_run_command` |
| **Honeypot start/stop** (Fase 2) | `start_honeypot`/`stop_honeypot` | `request_action` (`honeypot_start/stop`, altera estado → dry-run em lab/replay) → `honeypot.start/stop` |
| **Engenharia social** (Fase 2) | `generate_social_engineering_content` | overlay `precheck_runtime` (`social_engineering`; RBAC+auditoria, SEM gate — só gera texto) → `social_engineering.build_generation_request` |

> Cobrir o `noc_api` fecha o bypass pela API: a governança **não vale só para o
> agente**. Em modo lab/replay, esses endpoints viram dry-run.

As tools de alto impacto (Mikrotik write, ASN, BGP, BrbOS, exploit, hydra,
sqlmap) **já** passam pelo gate de aprovação `tools/risk.py` e estão modeladas no
`ACTION_CATALOG` — a migração para roteá-las explicitamente pelo Control Plane é
um próximo passo (a decisão da policy engine para elas já está testada).

## Tools do agente (governança)

`register_authorized_asset`, `list_authorized_assets`, `revoke_authorized_asset`,
`get_operating_mode`, `set_operating_mode`, `evaluate_action_policy` (simula a
decisão sem executar).

## Testes (Prioridade 10)

`tests/test_redaction.py`, `test_rbac.py`, `test_asset_registry.py`,
`test_policy_engine.py`, `test_control_plane.py` cobrem: role sem permissão →
DENY, alvo fora do inventário (modo estrito) → DENY, loopback/infra crítica →
DENY, modo lab/replay → DRY_RUN, exploração ativa sem toggle → DENY / com toggle
→ REQUIRE_APPROVAL, social sem engagement_reference → DENY, redaction de segredo,
prompt-injection tratada como dado inerte, e que DENY/DRY_RUN/REQUIRE_APPROVAL
**não executam** o executor.

## Entregue depois das fundações

- **P6 — Case management** ✅ `tools/incidents.py` + tabela `incidents`: casos com
  ciclo de vida (open→investigating→contained→resolved|false_positive), timeline,
  evidências, ações tomadas e eventos vinculados; redigido + auditado.
- **P7 — Auditoria assinada** ✅ `core/audit_signing.py`: HMAC opcional
  (`AUDIT_HMAC_SECRET`) num canal LATERAL (`event_signatures`, sem tocar a hash
  chain) + `verify_signatures` + export JSON; assina junto do checkpoint periódico.
- **P9 — Runbooks determinísticos** ✅ `core/response_playbooks.py`: DDoS, IP
  suspeito, honeypot hit, credential stuffing, queda de equipamento, drift de
  firewall, mudança no Mikrotik, brute force autorizado — cada ação candidata é
  classificada PELA própria policy engine (AUTO/APROVAÇÃO/DRY-RUN/BLOQUEADA),
  refletindo modo/toggles/papel/alvo. Complementa o motor de escalonamento
  `tools/playbook.py` (ATTACK_PLAYBOOKS), não o substitui.

## Entregue na rodada de integração

- **Integração total (alto risco)** ✅ Todas as tools que funilam por
  `tools/risk.request_confirmation` (exploit/hydra/sqlmap/Mikrotik write/BGP/ASN/
  BrbOS) passam por um **overlay do Control Plane** (`core/policy_engine.runtime_precheck`
  via `_governance_precheck`): RBAC + trava de segurança + modo operacional ANTES
  de criar a pendência. Em real+admin → comportamento de antes; lab/replay →
  dry-run sem pendência; alvo proibido / papel sem permissão → negado e auditado.
- **Roteamento explícito de SSH/social/honeypot (Fase 2)** ✅ `run_remote_command`
  (`ssh_command`) e `start_honeypot`/`stop_honeypot` (`honeypot_start/stop`) via
  `request_action` (honeypot altera estado → dry-run em lab/replay; SSH é
  read-only e roda em lab); `generate_social_engineering_content` via overlay
  `precheck_runtime` (RBAC+auditoria, SEM gate — só gera texto, envio já é manual).
  Toggle/engagement do social e allowlist do SSH seguem valendo como defesa em
  profundidade.
- **RBAC real (REST)** ✅ `config.NEXUS_ROLE_TOKENS` ('papel:token') + `require_token`
  resolve o papel; ações REST (block/unblock subscriber) passam o papel ao Control
  Plane. Token principal = admin (compatível). readonly/auditor → ação negada.
- **Auto-incidente** ✅ `incidents.auto_open_from_event` (opt-in `AUTO_INCIDENT_ENABLED`,
  idempotente por ip/kind, fail-safe) ligado ao hit de honeypot.

## Próximos passos (TODOs)

- ✅ ~~Roteamento explícito de SSH/social/honeypot~~ (Fase 2).
- ✅ ~~Segredos fora do `.env`~~ — Fase 1: Keychain do macOS (`core/secrets.py`,
  keychain-first + fallback `.env`); Vault continua como opção futura.
- ✅ ~~RBAC mais rico + usuários reais~~ — Fase 3: `core/users.py` + tabela
  `api_users` (token hasheado), `Principal`/`require_permission` no `api/server`,
  RBAC em billing/devices, CLI `scripts/nexus_users.py`. Resta propagar a
  identidade do chamador da API para as ações do AGENTE (hoje o agente age como
  admin independentemente do token REST) — próxima camada.
- **Modo no cliente**: negociar o modo visual do Tauri com o modo operacional do
  backend (header + decisão do servidor). — *Fase 4*
