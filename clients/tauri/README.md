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

## Usar
1. No topo, informe a **URL da API** (ex.: `http://127.0.0.1:8000`) e o **token**
   (`NEXUS_API_TOKEN` do `.env`; se vazio, o servidor imprime um temporário no
   stdout ao subir). Ambos ficam salvos localmente (localStorage).
2. **Consultas:** Visão geral · Assinantes · Equipamentos · Quedas · Eventos ·
   Autodiagnóstico.
3. **Ações:** digite o `id` do assinante e use Bloquear/Desbloquear; ou
   Cobrança (dry-run) e Checar equipamentos.

As ações de **alto risco** (exploração, ASN/BGP, RPZ) **não** estão nesta API —
continuam só pelo agente, atrás do gate de `tools/risk.py`.

## Estrutura
```
clients/tauri/
├── src/                # frontend React + TS
│   ├── api.ts          # wrapper REST (Bearer) via plugin HTTP do Tauri
│   ├── App.tsx         # UI: conexão, consultas, ações, log
│   ├── main.tsx
│   └── styles.css
├── src-tauri/          # shell nativo (Rust/Tauri v2)
│   ├── src/{main,lib}.rs
│   ├── Cargo.toml
│   ├── tauri.conf.json
│   └── capabilities/default.json   # permissão HTTP (escopo das URLs)
├── index.html · vite.config.ts · tsconfig*.json · package.json
```

### Segurança / produção
- Use **HTTPS** fora da LAN (o token vai no header).
- O escopo de URLs do HTTP está amplo em `capabilities/default.json`
  (`http://*/*` + `https://*/*`) para permitir apontar a API à mão; **restrinja**
  para o host real em produção.
- Token guardado em localStorage é conveniência; para produção, considere o
  `tauri-plugin-store`/keychain.
