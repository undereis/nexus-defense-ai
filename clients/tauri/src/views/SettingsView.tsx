import { useState } from "react";
import { Info, Settings } from "lucide-react";
import { useNexus } from "../lib/useNexus";
import { DataPanel } from "../components/DataPanel";
import { StatusPill } from "../components/StatusPill";

export function SettingsView() {
  const { baseUrl, token, setConfig, status } = useNexus();
  const [url, setUrl] = useState(baseUrl);
  const [tk, setTk] = useState(token);

  const tone = status === "ok" ? "ok" : status === "idle" ? "neutral" : "bad";

  return (
    <div className="grid cols-2">
      <DataPanel title="Conexão" icon={Settings}>
        <div className="field">
          <label>URL da API</label>
          <input value={url} onChange={(e) => setUrl(e.target.value)} />
        </div>
        <div className="field" style={{ marginTop: 10 }}>
          <label>Token (NEXUS_API_TOKEN)</label>
          <input type="password" value={tk} onChange={(e) => setTk(e.target.value)} />
        </div>
        <div className="row" style={{ marginTop: 12 }}>
          <button className="primary" onClick={() => setConfig(url.trim(), tk.trim())} disabled={!url.trim() || !tk.trim()}>
            Salvar e reconectar
          </button>
          <StatusPill tone={tone} label={status === "ok" ? "conectado" : status} />
        </div>
        <div className="muted-note" style={{ marginTop: 10 }}>
          Salvo localmente (localStorage). Use HTTPS fora da LAN.
        </div>
      </DataPanel>

      <DataPanel title="Sobre" icon={Info}>
        <p className="muted-note">
          Nexus Defense IA — Command Center (cliente Tauri + React). Consome a API REST do
          motor Python (contrato em <code>docs/api.md</code>). Esta interface só lê/age sobre os
          endpoints existentes — não há backend novo nem dados simulados.
        </p>
        <div className="section-title" style={{ marginTop: 14 }}>Ações indisponíveis na API atual</div>
        <p className="muted-note">
          Bloqueio de ASN, BGP FlowSpec, RPZ e exploração ativa NÃO estão na API REST — continuam
          só pelo agente do Nexus, atrás do gate de confirmação. Não são simuladas aqui.
        </p>
      </DataPanel>
    </div>
  );
}
