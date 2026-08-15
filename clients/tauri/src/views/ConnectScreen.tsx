import { useState } from "react";
import { Shield } from "lucide-react";
import { useNexus } from "../lib/useNexus";

export function ConnectScreen() {
  const { baseUrl, token, setConfig, status, error } = useNexus();
  const [url, setUrl] = useState(baseUrl);
  const [tk, setTk] = useState(token);

  return (
    <div className="connect">
      <div className="box panel">
        <div className="panel-head">
          <div className="brand-logo" style={{ width: 28, height: 28 }}><Shield size={15} /></div>
          <h3>Conectar ao Nexus Defense IA</h3>
        </div>
        <div className="panel-body">
          <div className="field">
            <label>URL da API</label>
            <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="http://127.0.0.1:8000" />
          </div>
          <div className="field">
            <label>Token (NEXUS_API_TOKEN)</label>
            <input type="password" value={tk} onChange={(e) => setTk(e.target.value)} placeholder="cole o token" />
          </div>
          {status === "unauthorized" ? (
            <div className="muted-note" style={{ color: "var(--bad)" }}>Token recusado (401). Verifique e tente de novo.</div>
          ) : null}
          {status === "offline" && error ? (
            <div className="muted-note" style={{ color: "var(--bad)" }}>{error}</div>
          ) : null}
          <button
            className="primary"
            style={{ marginTop: 10, width: "100%", justifyContent: "center" }}
            disabled={!url.trim() || !tk.trim()}
            onClick={() => setConfig(url.trim(), tk.trim())}
          >
            Conectar
          </button>
          <div className="muted-note" style={{ marginTop: 10 }}>
            O token permanece somente nesta sessão. Esta build conecta apenas à API local.
          </div>
        </div>
      </div>
    </div>
  );
}
