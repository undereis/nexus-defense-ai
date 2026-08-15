import { useState } from "react";
import { Info, Settings, FlaskConical, ShieldAlert } from "lucide-react";
import { useNexus } from "../lib/useNexus";
import { useEnvironment, MODE_DESC, MODE_LABEL } from "../lib/environment";
import { DataPanel } from "../components/DataPanel";
import { StatusPill } from "../components/StatusPill";
import { EnvironmentModePill } from "../components/EnvironmentModePill";

export function SettingsView() {
  const { baseUrl, token, setConfig, status } = useNexus();
  const { mode } = useEnvironment();
  const [url, setUrl] = useState(baseUrl);
  const [tk, setTk] = useState(token);

  const tone = status === "ok" ? "ok" : status === "idle" ? "neutral" : "bad";

  return (
    <div className="grid cols-2">
      <DataPanel title="Conexão" icon={Settings}>
        <div className="field">
          <label>URL da API</label>
          <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="http://127.0.0.1:8000" />
        </div>
        <div className="field" style={{ marginTop: 10 }}>
          <label>Token (NEXUS_API_TOKEN)</label>
          <input type="password" value={tk} onChange={(e) => setTk(e.target.value)} placeholder="cole o token" />
        </div>
        <div className="row" style={{ marginTop: 12 }}>
          <button className="primary" onClick={() => setConfig(url.trim(), tk.trim())} disabled={!url.trim() || !tk.trim()}>
            Salvar e reconectar
          </button>
          <StatusPill tone={tone} label={status === "ok" ? "conectado" : status} />
        </div>
        <div className="muted-note" style={{ marginTop: 10 }}>
          A URL fica em <code>localStorage</code>; o token permanece somente na sessão atual
          (<code>sessionStorage</code>). Esta distribuição aceita apenas a API local em
          <code> 127.0.0.1:8000</code> ou <code>localhost:8000</code>.
        </div>
      </DataPanel>

      <DataPanel title="Ambiente" icon={FlaskConical}>
        <div className="row" style={{ justifyContent: "space-between" }}>
          <span className="muted-note">Modo de visualização atual</span>
          <EnvironmentModePill />
        </div>
        <div className="muted-note" style={{ marginTop: 10 }}>
          <strong>{MODE_LABEL[mode]}</strong> — {MODE_DESC[mode]}
        </div>
        <ul className="env-list">
          <li><strong>Real</strong> — só dados reais da API; sem telemetria falsa.</li>
          <li><strong>Laboratório</strong> — demonstração visual de UX; conteúdo sem origem na API
            aparece marcado como “Simulação visual / demo local”.</li>
          <li><strong>Replay</strong> — reprodução de eventos; indisponível na API atual (conceitual).</li>
        </ul>
      </DataPanel>

      <DataPanel title="Sobre" icon={Info}>
        <p className="muted-note">
          Nexus Defense IA — Command Center (cliente Tauri + React). Consome a API REST do
          motor Python (contrato em <code>docs/api.md</code>). Esta interface só lê/age sobre os
          endpoints existentes — não há backend novo nem dados simulados como reais.
        </p>
        <div className="section-title" style={{ marginTop: 14 }}>Ações indisponíveis na API atual</div>
        <p className="muted-note">
          Bloqueio de ASN, BGP FlowSpec, RPZ e exploração ativa NÃO estão na API REST — continuam
          só pelo agente do Nexus, atrás do gate de confirmação. Não são simuladas aqui.
        </p>
      </DataPanel>

      <DataPanel title="Recomendações de produção" icon={ShieldAlert}>
        <ul className="env-list">
          <li><strong>Token:</strong> mantido apenas durante a sessão. Para persistência futura,
            use o Keychain; nunca volte a gravá-lo em <code>localStorage</code>.</li>
          <li><strong>HTTP:</strong> a capability está limitada à API local na porta 8000.</li>
          <li><strong>CSP:</strong> política restritiva aplicada no shell Tauri.</li>
          <li><strong>API remota:</strong> exige uma build específica com domínio HTTPS explícito
            na capability; curingas não são aceitos.</li>
          <li>O <code>.app</code> ainda <strong>não é assinado/notarizado</strong>; faça-o antes de distribuir.</li>
        </ul>
      </DataPanel>
    </div>
  );
}
