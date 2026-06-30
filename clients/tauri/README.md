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

> ⚠️ **Honestidade:** este código foi escrito e revisado, mas **não foi
> compilado** no ambiente onde nasceu (não há Rust/cargo lá). Compile no seu
> Mac; ajustes pequenos de versão de plugin/Tauri podem ser necessários.

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
pelo agente, atrás do gate de `tools/risk.py`.

## Estrutura
```
clients/tauri/
├── src/
│   ├── api.ts                 # wrapper REST (Bearer) via plugin HTTP do Tauri (INALTERADO)
│   ├── App.tsx                # provider + shell
│   ├── lib/
│   │   ├── useNexus.tsx       # estado central: fetch/poll/estados (ok/offline/401)
│   │   ├── format.ts          # severidade, tempo relativo, IP inconsistente, risco
│   │   ├── insights.ts        # "Nexus IA" — insights derivados dos dados reais
│   │   └── nav.ts             # itens da sidebar
│   ├── components/            # AppShell, Sidebar, Topbar, MetricCard, DataPanel,
│   │   │                      # CommandCenter, ThreatMapPlaceholder, EventsTimeline,
│   │   │                      # NexusInsights, QuickActions, StatusPill, Tables,
│   │   │                      # SubscriberAction, states (loading/erro/offline/vazio)
│   ├── views/                # Dashboard/Defesa/Mapa/Mikrotik/Firewall/IA/Analytics/
│   │   │                      # ThreatIntel/Logs/Settings/ConnectScreen + registry
│   ├── main.tsx · styles.css  # tema dark premium SOC/NOC
├── src-tauri/                 # shell nativo (Rust/Tauri v2) — inalterado
└── index.html · vite.config.ts · tsconfig*.json · package.json
```

### Segurança / produção
- Use **HTTPS** fora da LAN (o token vai no header).
- O escopo de URLs do HTTP está amplo em `capabilities/default.json`
  (`http://*/*` + `https://*/*`) para permitir apontar a API à mão; **restrinja**
  para o host real em produção.
- Token guardado em localStorage é conveniência; para produção, considere o
  `tauri-plugin-store`/keychain.
