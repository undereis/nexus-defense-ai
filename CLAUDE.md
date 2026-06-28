# CLAUDE.md

> Mantenha este arquivo curto — é carregado em todo contexto.
> Detalhes longos vão em `/docs/` e são lidos sob demanda.

## Projeto

Sistema de defesa autônoma de rede assistido por IA (LangGraph + Claude).
Detecta ataques em tempo real, executa resposta escalonada (throttle → isolamento → BGP
FlowSpec → ASN block), mantém trilha de auditoria com hash chain e opera via CLI
interativa ou API REST.

## Stack

- **Runtime:** Python 3.14 · LangGraph · Claude (Anthropic API)
- **Persistência:** SQLite (`nexus.db`) — 20+ tabelas, hash chain de auditoria, FTS5
- **Firewall:** pfctl (macOS) · iptables + ipset `hash:net` (Linux)
- **API REST:** FastAPI (`api/server.py`) com autenticação por token
- **Integrações:** Mikrotik RouterOS · BrbOS (DNS da BrByte, RPZ) · BGP FlowSpec (ExaBGP) · AbuseIPDB · VirusTotal · Shodan · RIPEstat · Suricata DPI · Slack webhook

## Comandos

- **Testar:**         `venv/bin/pytest --tb=line -q`
- **Testar (fase4):** `venv/bin/pytest tests/test_playbook.py tests/test_asn_block.py -v`
- **Testar (fase5):** `venv/bin/pytest tests/test_infrastructure.py tests/test_asset_inventory.py tests/test_client_baseline.py tests/test_dns_monitor.py tests/test_brbos.py -v`
- **Lint:**           `venv/bin/ruff check .` (requer `pip install ruff` — não vem no venv)
- **CLI:**            `venv/bin/python main.py`
- **API:**            `venv/bin/uvicorn api.server:app --reload`

## Regras invioláveis

- `_AUTO_CAP = 2` em `tools/playbook.py` é **hardcoded** — nível 3 (BGP FlowSpec)
  **nunca executa automaticamente**, independente do valor de `PLAYBOOK_AUTO_LEVEL`.
- Toda ação de BGP e ASN block passa por gate de confirmação fora de banda (`tools/risk.py`).
- `ALLOW_ACTIVE_EXPLOITATION`, `ALLOW_ASN_BLOCK`, `ALLOW_BGP_FLOWSPEC` e `ALLOW_BRBOS_BLOCK`
  são **false** por padrão. Não ativar sem contexto explícito do operador.
- Bloqueio de domínio no DNS (RPZ via BrbOS) passa **sempre** pelo gate de confirmação
  (`tools/risk.py`), mesmo com `ALLOW_BRBOS_BLOCK=true`; e a Nexus **nunca** bloqueia
  domínio da própria infraestrutura (`_is_protected_domain` + `BRBOS_PROTECTED_DOMAINS`).
- Mudanças em lógica de firewall ou playbook exigem que a suite de testes passe.
- Nunca remover ou afrouxar o gate de confirmação de `tools/risk.py`.

## Convenções de código

- **Monkeypatch nos testes:** sempre usar object-form `monkeypatch.setattr(module.attr, ...)`,
  nunca string-form `"tools.foo.bar"` — falha quando o intermediário é módulo, não pacote.
- **imports de firewall em tools:** fazer no topo do módulo (não lazy dentro de função),
  para que `module.firewall` exista como atributo e possa ser mockado.
- **ipsets:** sempre `hash:net` para CIDRs (ASN block); `hash:ip` para IPs individuais.
- **Rate limiting:** pf usa `overload <nexus_blocklist>` (kernel auto-promove);
  iptables usa `hashlimit` + burst.
- Todo novo tipo de ataque em `ATTACK_PLAYBOOKS` precisa de entrada nos testes de playbook.

## Não fazer

- Não habilitar automação de BGP ou ASN block sem confirmação explícita do operador.
- Não usar `shell=True` em `subprocess` — risk of command injection.
- Não remover `_is_safe_to_isolate()` — protege loopback e IPs críticos da infraestrutura
  (DNS servers, roteadores marcados com `is_critical=True`) de auto-bloqueio.
- Não commitar `.env` com tokens reais — usar `.env.example` como referência.
- Não recarregar módulos com `importlib.reload()` dentro de testes — desfaz monkeypatches.
- **Nunca** rodar probe/scan/descoberta de API contra infraestrutura de **PRODUÇÃO** —
  em especial os resolvers DNS (BrbOS): são sensíveis a carga e rajadas de login
  disparam o anti-brute-force, podendo travar a rede inteira (já aconteceu: derrubou
  o DNS e exigiu reboot). Calibração só contra instância **local/lab**. Um login, zero
  retry-loop, reaproveitar cookie.

## Onde está o quê

- **Agente LangGraph:** `agents/nexus_agent.py` (137 tools registradas)
- **Engine de playbooks:** `tools/playbook.py`
- **Gate de confirmação:** `tools/risk.py`
- **Firewall abstrato:** `tools/firewall.py` → backends em `tools/firewall_backends/`
- **Banco de dados:** `database/db.py` (schema + CRUD completo)
- **Config central:** `config.py` (todos os toggles de feature)
- **Mapa de infraestrutura própria:** `tools/infrastructure.py` (IPs críticos nunca auto-bloqueados)
- **Conhecimento da rede (Fase 5):** `tools/asset_inventory.py` · `tools/client_baseline.py` · `tools/dns_monitor.py`
- **DNS por dentro (BrbOS):** `tools/brbos.py` (API REST do resolver: stats + RPZ block/unblock + rate limit; escrita gated)
- **Contra-inteligência (Fase 6):** `tools/ttp_profile.py` (perfil de grupo por TTPs: clustering determinístico de atacantes por comportamento/ASN/técnica) · `tools/tool_fingerprint.py` (fingerprint da ferramenta do atacante: User-Agent/credenciais/comportamento → sqlmap/Nmap/Mirai/etc., por assinatura). Ambos read-only.
- **Testes:** `tests/` (58 arquivos, ~584 passando; 14 falham só no sandbox: socket/ping/recon)
- **Base de conhecimento:** `workdir/apostilas/` (16 apostilas ingeridas via RAG)
- **Docs detalhadas:** `/docs/` (ler só quando a tarefa exigir)
