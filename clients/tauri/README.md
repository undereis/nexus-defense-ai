# Cliente desktop (Tauri + React) — Nexus Defense AI

Interface visual **nativa para macOS** (Tauri v2 + React + TypeScript) que
substitui o antigo cliente Delphi. Segue a mesma arquitetura: o **motor fica em
Python** (servidor Linux) e esta GUI é um **cliente** sobre a API REST `/api/*`
(contrato em [`../../docs/api.md`](../../docs/api.md)). Nada do motor, da API, da
lógica de negócio ou do banco foi alterado — só a camada de interface.

> Por que Tauri e não browser puro: as requisições saem pelo **plugin HTTP do
> Tauri** (`@tauri-apps/plugin-http`), que executa no Rust (nativo). Isso
> **dispensa CORS** no servidor — por isso a API e a autenticação continuam
> exatamente como estão.

> ✅ **Estado:** compila e empacota no macOS (arm64) — `.app`/`.dmg` gerados com
> Rust 1.96 + Tauri v2. O `.app` ainda **não é assinado/notarizado** (1ª abertura:
> clique-direito → Abrir, ou `xattr -dr com.apple.quarantine "Nexus Client.app"`).

## Pré-requisitos (macOS)
- **Node** ≥ 18 (testado com a versão do seu ambiente) e **npm**.
- **Rust** (rustup): `curl https://sh.rustup.rs -sSf | sh`
- **Xcode Command Line Tools**: `xcode-select --install`
- Tauri CLI vem como devDependency (`npm install` resolve).

## Rodar (dev)
```bash
cd clients/tauri
npm install
# ícones do app (uma vez): gere a partir de um PNG quadrado seu
npm run tauri icon caminho/para/logo.png
# sobe o motor em outro terminal, na raiz do repo:
#   venv/bin/uvicorn api.server:app --host 0.0.0.0 --port 8000
npm run tauri dev
```

## Empacotar (.app/.dmg para macOS)
```bash
npm run tauri build
```
O `.app`/`.dmg` sai em `src-tauri/target/release/bundle/`.

## Usar (Command Center)
1. Na tela de conexão, informe a **URL da API** (ex.: `http://127.0.0.1:8000`) e o
   **token** (`NEXUS_API_TOKEN` do `.env`; se vazio, o servidor imprime um
   temporário no stdout ao subir). Ficam salvos localmente (localStorage) e podem
   ser trocados depois em **Configurações**.
2. **Topbar:** status da API (online/offline/token inválido), última atualização
   (com aviso de "possivelmente vencido") e botão Atualizar. Os dados fazem
   **auto-refresh a cada 15s** via `/api/overview`.
3. **Sidebar:** Dashboard · Defesa · Mapa · Mikrotik · Firewall · IA · Analytics ·
   Threat Intelligence · Logs · Configurações.
4. **Dashboard:** cards de estado, **Mapa de Ameaças** (visualização ilustrativa
   com IPs reais da blocklist), **Centro de Operações** (nível de risco),
   **Nexus IA — Insights** (calculados no app a partir dos dados reais, incl.
   detecção de inconsistências como loopback/IP privado bloqueado), timeline de
   eventos por severidade, IPs bloqueados, quedas e **Ações rápidas**.

Tudo usa **dados reais** da API. Onde não há endpoint (ex.: Mikrotik), a seção
aparece como **"indisponível na API atual"** — nada é simulado. As ações de
**alto risco** (exploração, ASN/BGP, RPZ) **não** estão na API — continuam só
pelo agente, atrás do gate de `tools/risk.py`. Ações **efetivas** (bloquear/
desbloquear assinante) exigem **confirmação explícita** antes de chamar a API.

## Modos de visualização (Real / Laboratório / Replay)

O projeto ainda não está conectado a hardware/laboratório real. Para ser honesto
sobre a origem dos dados, a interface opera em três modos, alternáveis pelo
seletor na **Topbar** (e descritos em **Configurações → Ambiente**). A escolha é
puramente de frontend (salva em `localStorage`) e **nunca fabrica telemetria como
se fosse real** — só muda como a ausência/origem dos dados é apresentada.

| Modo | O que faz |
|---|---|
| **Real** (padrão) | Usa exclusivamente os dados reais da API. Indica "Dados reais da API". Sem telemetria falsa. Onde não há dado real (ex.: mapa sem IPs), mostra empty state profissional. |
| **Laboratório / Simulado** | Para demonstração visual de UX. Conteúdo sem origem na API (ex.: nós do mapa) aparece **marcado** como "Simulação visual / demo local". As métricas reais continuam reais e rotuladas — nada é misturado sem sinalização. Os nós de demonstração são **anônimos** (sem IP/país/cidade inventados). |
| **Replay** | Reprodução de eventos passados — preparada conceitualmente. Como não há endpoint/dados de replay, aparece como **"indisponível na API atual"**. Não cria backend nem arquivo de dados. |

Um **indicador global de fonte dos dados** (faixa sob a Topbar) combina o modo
com o estado da conexão: *API online / offline / token inválido / sem laboratório
conectado / visualização ilustrativa*. O painel **"Estado do Ambiente"** no
Dashboard (checklist de prontidão: API · Fonte · Laboratório físico · Hardware ·
Mapa · Replay) deixa claro que esta é uma **fase normal de implantação**, não um
erro — pronta para conectar hardware real no futuro.

## Estrutura
```
clients/tauri/
├── src/
│   ├── api.ts                 # wrapper REST (Bearer) via plugin HTTP do Tauri (INALTERADO)
│   ├── App.tsx                # provider + shell
│   ├── lib/
│   │   ├── useNexus.tsx       # estado central: fetch/poll/estados (ok/offline/401)
│   │   ├── environment.tsx    # modo Real/Lab/Replay (frontend, persistido)
│   │   ├── readiness.ts       # "Estado do Ambiente" derivado dos dados reais
│   │   ├── format.ts          # severidade, tempo relativo, IP inconsistente, risco
│   │   ├── insights.ts        # "Nexus IA" — insights + prontidão/preparação
│   │   └── nav.ts             # itens da sidebar
│   ├── components/            # AppShell, Sidebar, Topbar, MetricCard, DataPanel,
│   │   │                      # CommandCenter, ThreatMapPlaceholder, EventsTimeline,
│   │   │                      # NexusInsights, QuickActions, StatusPill, Tables,
│   │   │                      # SubscriberAction, states (loading/erro/offline/vazio),
│   │   │                      # DataSourceBanner, EnvironmentModePill, SimulationNotice,
│   │   │                      # HardwareEmptyState, OperationalReadinessChecklist,
│   │   │                      # LabReadinessPanel
│   ├── views/                # Dashboard/Defesa/Mapa/Mikrotik/Firewall/IA/Analytics/
│   │   │                      # ThreatIntel/Logs/Settings/ConnectScreen + registry
│   ├── main.tsx · styles.css  # tema dark premium SOC/NOC
├── src-tauri/                 # shell nativo (Rust/Tauri v2) — inalterado
└── index.html · vite.config.ts · tsconfig*.json · package.json
```

### Segurança / produção
- O **token** nunca é exibido em texto claro (campo mascarado) e vai só no header
  `Authorization: Bearer`. Guardado em `localStorage` por conveniência de dev;
  para produção, considere `tauri-plugin-store`/keychain. *(documentado na UI em
  Configurações → Recomendações de produção)*
- Use **HTTPS** fora da LAN (o token vai no header).
- O escopo de URLs do HTTP está amplo em `capabilities/default.json`
  (`http://*/*` + `https://*/*`) para permitir apontar a API à mão; **restrinja**
  para o host real em produção. *Não foi estreitado aqui para não quebrar o dev.*
- O **CSP** está em `null` em `tauri.conf.json`; defina uma política restritiva ao
  distribuir. *Documentado, não alterado.*

## Limitações atuais (sem hardware/laboratório)
- **Mikrotik/RouterOS:** a API REST não expõe esses endpoints hoje → seção mostra
  "Aguardando laboratório / hardware". O motor Python já tem as tools.
- **Mapa:** sem GeoIP na API → ilustrativo (IPs reais, posições esquemáticas).
- **Replay:** sem endpoint/dados → "indisponível na API atual".
- **Equipamentos físicos:** enquanto não houver devices cadastrados/conectados, o
  "Estado do Ambiente" indica "hardware ausente" — sem inventar telemetria.
