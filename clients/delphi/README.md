# Cliente Delphi (FMX) — Nexus Defense AI

Interface visual de referência em **Delphi**, seguindo a arquitetura defendida:
o **motor fica em Python** (servidor Linux) e a GUI é um **cliente fino sobre a
API REST** (contrato em [`../../docs/api.md`](../../docs/api.md)). Nada de
Python embutido — desacoplado, e você aproveita seu Delphi.

> ⚠️ **Honestidade:** este código foi escrito e revisado, mas **não foi
> compilado** no ambiente onde nasceu (não há Delphi lá). Abra no Delphi para
> compilar; ajustes pequenos de unit/versão podem ser necessários conforme a
> sua edição.

## Arquivos
- `uNexusApi.pas` — wrapper REST: autenticação por token (Bearer), GET/POST,
  desserialização JSON. É a peça reutilizável (sirva-se dela em qualquer app).
- `uMainForm.pas` — formulário FMX **construído em código** (sem `.fmx`): tela
  de conexão (URL + token), botões de consulta e de ação, e um log.
- `NexusClient.dpr` — projeto.

## Requisitos
- Delphi 10.x ou superior (Community Edition serve) com **FMX** (FireMonkey).
- Funciona em **Windows**; FMX é multiplataforma (macOS/…); Linux exige FMXLinux.
- Sem bibliotecas externas — só `System.Net.HttpClient` e `System.JSON`.

## Como compilar
1. Suba o motor: `venv/bin/uvicorn api.server:app --host 0.0.0.0 --port 8000`
   (em produção, atrás de HTTPS).
2. No Delphi: **File → Open…** e escolha `NexusClient.dpr`. O IDE gera o
   `.dproj` e o `NexusClient.res` automaticamente.
3. **Run** (F9).

(Alternativa: crie um *Multi-Device Application* em branco, adicione
`uNexusApi.pas` e `uMainForm.pas` ao projeto e copie o conteúdo do `.dpr`.)

## Como usar
1. No topo, informe a **URL da API** (ex.: `http://127.0.0.1:8000`) e o
   **token** (`NEXUS_API_TOKEN` do `.env`; se vazio, o servidor imprime um
   temporário no stdout ao subir).
2. **Consultas:** Visão geral · Assinantes · Equipamentos · Quedas · Eventos ·
   Autodiagnóstico.
3. **Ações:** digite o `id` do assinante e use Bloquear/Desbloquear; ou
   Cobrança (dry-run) e Checar equipamentos.

As ações de alto risco (exploração, ASN/BGP, RPZ) **não** estão nesta API —
continuam só pelo agente, atrás do gate de `tools/risk.py`.

## Próximos passos (para um app de produção)
- Trocar o `TMemo` por `TStringGrid`/`TListView` por recurso.
- Polling/refresh automático (TTimer) sobre `/api/overview`.
- Guardar URL/token com segurança (não em texto puro).
- HTTPS obrigatório fora da LAN.
