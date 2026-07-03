# Session Handoff — CP-SD (Control Plane como porta única de saída)

> Documento de continuidade entre sessões para o arco de segurança **CP-SD**.
> Atualizado a cada fase commitada. Não é um doc de arquitetura (ver
> `docs/control_plane.md` para isso) — é um handoff de estado/pendências.

## Estado atual

**O Control Plane ainda NÃO é porta única de saída.** O arco segue em
andamento, fase a fase, fechando bypasses um de cada vez. Não declarar
vitória final até todos os itens da seção "Pendências" estarem resolvidos.

Protocolo de cada fase (repetido desde a Fase 1A): scoping/leitura antes de
implementar quando a fase pedir; mudança pequena e testável; suíte +
`ruff check .` verdes; **nunca commitar sem autorização explícita do
operador**, com mensagem e lista de arquivos exatos fornecidos por ele; nunca
`git push`.

## Último commit funcional

`28e1503` — CP-SD Fase 6H: governar forward SIEM pelo Control Plane

## Fases concluídas (commits, mais recentes primeiro)

- `28e1503` **Fase 6H** — `tools/siem.py:forward_new_events` (envio real ao SIEM
  externo) governado pelo Control Plane.
- (sem commit) **Fase 6G** — scoping read-only do `siem_loop`/`tools/siem.py`.
- `e7907b8` **Fase 6F** — disparo de `run_billing_cycle` auditado pelo Control Plane.
- (sem commit) **Fase 6E** — scoping read-only do disparo `run_billing_cycle`.
- `3e41454` **Fase 6D** — `block_subscriber`/`unblock_subscriber` (billing) governados.
- (sem commit) **Fase 6C** — scoping read-only do `subscriber_billing_loop`/billing/Mikrotik.
- `f29b4cc` **Fase 6B** — 4 loops internos simples (`risk_sweep_loop`,
  `audit_checkpoint_loop`, `watchdog_loop`, `report_loop`) migrados ao CP.
- (sem commit) **Fase 6A** — auditoria read-only dos loops diretos de `main.py`.
- `af676b3`/`e22a4fd`/`965f702`/`646d0b5` — Fases 5D/5C/5B/5A (Service Principals
  + `monitor_loop`/`proactive_audit_loop`/`reconcile_loop`).
- `7e4d133`/`9b45d67`/`e26700c`/`2c1850e`/`4c597da`/`a3665be`/`7dd7a59` — Fases
  4B/4A/3/2B/2/1B/1A (fundações: propagação de Principal, cinto de modo,
  tools diretas do agente, deception/honeytoken, rede de testes).

## Resumo das fases recentes (6B → 6H)

**Fase 6B** — loops internos simples migrados: `risk_sweep_loop`,
`audit_checkpoint_loop`, `watchdog_loop`, `report_loop`. Action types novos:
`risk.sweep_expired`, `audit.checkpoint`, `watchdog.check_health`,
`report.generate`. Papel `service` ganhou permissões específicas, sem
wildcard/admin.

**Fase 6C** (scoping) — achado: `run_billing_cycle` já existia como
action_type HIGH/`noc.billing`/`changes_state=True`; gateá-lo inteiro
quebraria a automação diária por `REQUIRE_APPROVAL`. Recomendação: o
boundary certo é `block_subscriber`/`unblock_subscriber` dentro de
`tools/billing.py`.

**Fase 6D** — `block_subscriber`/`unblock_subscriber` passaram pelo Control
Plane; Mikrotik só é chamado em ALLOW (DENY/DRY_RUN_ONLY nunca tocam
Mikrotik). **Bug crítico de identidade encontrado e corrigido**: a versão
inicial sobrescrevia incondicionalmente o Principal real por
`SERVICE_BILLING_PRINCIPAL` — corrigido com um helper que só usa o Service
Principal quando `cp.get_current_principal() is None`; se já existe Principal
humano/integrado, ele é preservado. Papel `service` ganhou
`noc.block_subscriber`/`noc.unblock_subscriber` (sem `noc.billing`, sem
wildcard). `tools/mikrotik.py` não foi tocado.

**Fase 6E** (scoping) — mutação já protegida pela 6D; faltava auditabilidade
do EVENTO de disparo do ciclo. Usar o action_type antigo `run_billing_cycle`
(HIGH) travaria o job automático. Recomendação: trigger audit-only,
`changes_state=False`.

**Fase 6F** — `run_billing_cycle` passou a gerar evento auditável
(`billing.run_cycle.trigger`, `changes_state=False`, `ActionRisk.LOW`, sem
aprovação), centralizado dentro de `tools/billing.py`. Cobriu automaticamente
`subscriber_billing_loop`, REST `/api/billing/run` e o agente
`run_billing_cycle_now`. REST passou a preservar `actor`/`role` do token.
`noc_operator` (papel humano) ganhou `billing.run_cycle.trigger` para não
regredir o uso legítimo da REST; `service` também ganhou. Job automático não
foi travado; mutação real seguiu protegida pela 6D.

**Fase 6G** (scoping) — achado: `siem_loop` → `tools/siem.py:forward_new_events`
lê a tabela `events` e envia a um destino externo (Elastic/Splunk/webhook) via
`requests.post`. `SIEM_MODE=off`/`SIEM_URL=""` por padrão. Não havia
action_type, RBAC nem cinto lab/replay em `tools/siem.py`. A tool do agente
`siem_forward_now` também chamava `forward_new_events` direto. Conclusão:
diferente do trigger de billing, SIEM precisa ser **enforcement**
(`changes_state=True`) — envia dados para fora do Nexus.

**Fase 6H** — `forward_new_events` passou pelo Control Plane. Novo action_type
`siem.forward_events` (permission igual, `changes_state=True`,
`ActionRisk.MEDIUM`, sem `requires_approval`). Papel `service` ganhou só essa
permissão; nenhum papel humano foi alterado. Principal real preservado quando
existe; `SERVICE_SIEM_PRINCIPAL` só é usado quando não há Principal atual. Em
lab/replay, `siem.forward_events` vira `DRY_RUN_ONLY` e `requests.post` nunca
é chamado. DENY/DRY_RUN nunca avançam o cursor; ALLOW chama o sender e só
avança o cursor se o destino confirmar. `siem_forward_now` (agente) ficou
protegido indiretamente, sem editar `agents/nexus_agent.py`.
`siem_status`/`describe_status` seguem leitura pura, sem CP. `main.py` e
`agents/nexus_agent.py` não foram tocados.

## Achado importante da Fase 6H — feedback loop SIEM/Control Plane

O SIEM agora audita seu próprio envio via Control Plane. Como os eventos
`control_plane_decision`/`control_plane_executed` são gravados na MESMA
tabela `events` que o SIEM varre, um envio bem-sucedido deixa ~2 eventos
novos para o próximo ciclo:

```
SIEM envia eventos → CP registra decisão/execução → esses registros entram
em `events` → o próximo ciclo exporta esses registros → o novo envio gera
novos registros → ...
```

**Isso não foi corrigido na Fase 6H, de propósito.** Filtrar esses eventos
mudaria o contrato do que o SIEM exporta — decisão de produto/arquitetura,
não uma correção óbvia. Fica para uma fase própria de scoping.

## Próxima fase recomendada

**CP-SD Fase 6I — scoping do feedback loop SIEM/Control Plane.**

Objetivo: decidir se os eventos do próprio `siem.forward_events` devem ser
exportados normalmente, filtrados, marcados como internos, agregados,
exportados com rate limit, ou mantidos como estão hoje. Não implementar
antes do scoping. Avaliar impacto em auditoria, custo, ruído e completude
forense. Decidir se `control_plane_decision`/`control_plane_executed`
devem ser exportados ao SIEM sempre, nunca, ou com exceção só para
`siem.forward_events`.

## Pendências restantes do CP-SD

- **CP-SD Fase 6I** — feedback loop SIEM/Control Plane (ver acima).
- `threat_feed_refresh_loop`.
- `asset_inventory_loop`.
- `dns_monitor_loop` (cautela redobrada — incidente histórico contra o
  resolver BrbOS; nunca fazer probe/scan contra produção).
- `device_monitor_loop`.
- `monitor_loop` — `firewall.block_ip` ainda é chamada direta (só o
  `ask_agent` daquele loop tem Service Principal).
- `reconcile_loop` — `check_and_reconcile(auto_reapply=True)` ainda é
  chamada direta (mesma situação).
- `tools/risk.py:_TOOL_ACTION_MAP` ainda tem lacunas conhecidas
  (`network_device_run_command`, billing, SIEM não mapeados ali —
  contornado via CP, não corrigido na fonte).
- `tools/mikrotik.py` ainda não tem cinto lab/replay direto (a proteção do
  billing vem inteiramente de fora, via CP).
- Honeypot/honeytoken listeners fora de `main.py`.
- Consolidação futura da suíte de segurança em invariantes permanentes (hoje
  vários testes fixam "o estado atual da fase X", exigindo ajuste a cada
  fase nova — padrão aceito e documentado, mas vale uma consolidação um dia).
- **Roles granulares por serviço** — dívida técnica registrada: hoje todo
  `service:*` compartilha o mesmo papel RBAC `"service"`. Evitar
  wildcard/admin continua valendo; papéis como `service_billing`,
  `service_siem`, `service_watchdog` podem ser avaliados no futuro se a
  granularidade por ATOR não for mais suficiente (hoje o `action_type`
  já dá granularidade de auditoria mesmo com um único papel).
- Deny-por-padrão (`_DEFAULT_SPEC` → DENY) só depois de catalogar todos os
  action_types + telemetria.
- Segredos em Vault (além do Keychain da Fase 1).

## Regras/decisões arquiteturais consolidadas (repetir em toda fase nova)

- Service Principal só deve ser usado quando não há Principal atual no
  ContextVar (`cp.get_current_principal() is None`).
- Nunca sobrescrever Principal humano/integrado já propagado — se já existe,
  preservar `actor`/`role` reais (lição da Fase 6D, aplicada desde o design
  a partir da 6H).
- Não usar `admin` como fallback para jobs automáticos.
- Não declarar o Control Plane como porta única até fechar todos os
  bypasses listados em "Pendências".
- Não dar wildcard (`*`, `noc.*`, `siem.*`, `billing.*`) ao papel `service`.
- Não abrir `.env`; não tocar `database/nexus.db`.
- Não executar integrações reais (Mikrotik, SIEM, rede) sem lab/hardware
  explícito — nunca em testes.
- Quando múltiplos call-sites convergem para a mesma função de side effect
  real (ex.: loop automático + tool do agente + REST), preferir o boundary
  DENTRO dessa função (não em cada call-site) — evita duplicação e
  inconsistência (padrão validado em billing e SIEM).

## Estado de testes (últimas fases)

| Fase | `tests/security/` | Suíte completa | ruff |
|---|---|---|---|
| 6F | 189 passed | 1135 passed | limpo |
| 6H | 205 passed | 1151 passed | limpo |

Nota: `tests/test_whois_lookup.py` e ocasionalmente `tests/test_asn_block.py`
dependem de rede real/estado entre testes e são intermitentes — não
relacionados a este arco (confirmados passando isolados e em reexecução
completa).

## Arquivos tocados pela Fase 6H (referência)

- `tools/siem.py`
- `core/policy_engine.py`
- `core/rbac.py`
- `tests/security/test_siem_control_plane.py`
- `tests/security/test_billing_control_plane.py`
- `tests/test_siem.py`
