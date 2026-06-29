import { useState } from "react";
import { NexusApi } from "./api";

// Resultado atualmente exibido no painel central (união discriminada).
type Result =
  | { kind: "overview"; data: any }
  | { kind: "subscribers"; rows: any[] }
  | { kind: "devices"; rows: any[] }
  | { kind: "outages"; rows: any[] }
  | { kind: "events"; rows: any[] }
  | { kind: "health"; text: string }
  | { kind: "message"; title: string; text: string }
  | null;

export default function App() {
  const [baseUrl, setBaseUrl] = useState(
    localStorage.getItem("nexus_url") || "http://127.0.0.1:8000"
  );
  const [token, setToken] = useState(localStorage.getItem("nexus_token") || "");
  const [subId, setSubId] = useState("");
  const [result, setResult] = useState<Result>(null);
  const [log, setLog] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);

  function api(): NexusApi {
    localStorage.setItem("nexus_url", baseUrl);
    localStorage.setItem("nexus_token", token);
    return new NexusApi(baseUrl, token);
  }

  function addLog(s: string) {
    const stamp = new Date().toLocaleTimeString();
    setLog((l) => [`${stamp}  ${s}`, ...l].slice(0, 120));
  }

  async function run(label: string, fn: () => Promise<void>) {
    setBusy(true);
    try {
      await fn();
    } catch (e: any) {
      addLog(`ERRO (${label}): ${e?.message || e}`);
    } finally {
      setBusy(false);
    }
  }

  // --- consultas ---
  const doOverview = () =>
    run("visão geral", async () => {
      setResult({ kind: "overview", data: await api().overview() });
      addLog("Visão geral carregada.");
    });
  const doSubscribers = () =>
    run("assinantes", async () => {
      const d = await api().subscribers();
      setResult({ kind: "subscribers", rows: d.subscribers });
      addLog(`Assinantes: ${d.subscribers.length}`);
    });
  const doDevices = () =>
    run("equipamentos", async () => {
      const d = await api().devices();
      setResult({ kind: "devices", rows: d.devices });
      addLog(`Equipamentos: ${d.devices.length}`);
    });
  const doOutages = () =>
    run("quedas", async () => {
      const d = await api().outages("aberto");
      setResult({ kind: "outages", rows: d.outages });
      addLog(`Quedas abertas: ${d.outages.length}`);
    });
  const doEvents = () =>
    run("eventos", async () => {
      const d = await api().events(24);
      setResult({ kind: "events", rows: d.events });
      addLog(`Eventos 24h: ${d.events.length}`);
    });
  const doHealth = () =>
    run("autodiagnóstico", async () => {
      const d = await api().health();
      setResult({ kind: "health", text: d.report });
      addLog("Autodiagnóstico carregado.");
    });

  // --- ações ---
  const doBlock = () =>
    run("bloquear", async () => {
      if (!subId.trim()) return addLog("Informe o id do assinante.");
      const d = await api().block(subId.trim(), "bloqueio via cliente Tauri");
      setResult({ kind: "message", title: "Bloquear", text: d.message });
      addLog(`Bloquear ${subId}: ${d.message}`);
    });
  const doUnblock = () =>
    run("desbloquear", async () => {
      if (!subId.trim()) return addLog("Informe o id do assinante.");
      const d = await api().unblock(subId.trim(), "desbloqueio via cliente Tauri");
      setResult({ kind: "message", title: "Desbloquear", text: d.message });
      addLog(`Desbloquear ${subId}: ${d.message}`);
    });
  const doBillingDry = () =>
    run("cobrança dry-run", async () => {
      const d = await api().runBilling(true);
      setResult({ kind: "message", title: "Cobrança (dry-run)", text: d.message });
      addLog("Ciclo de cobrança (dry-run) executado.");
    });
  const doCheckDevices = () =>
    run("checar equipamentos", async () => {
      const d = await api().checkDevices();
      const t: string[] = d.transitions || [];
      setResult({
        kind: "message",
        title: "Checagem de equipamentos",
        text: t.length ? t.join("\n") : "Sem transições.",
      });
      addLog(`Checagem: ${t.length} transição(ões).`);
    });

  return (
    <div className="app">
      <header>
        <h1>Nexus Defense AI — Cliente</h1>
        <span className="muted">{busy ? "carregando…" : "pronto"}</span>
      </header>

      <div className="bar">
        <label>API</label>
        <input
          className="grow"
          value={baseUrl}
          onChange={(e) => setBaseUrl(e.target.value)}
          placeholder="http://127.0.0.1:8000"
        />
        <label>Token</label>
        <input
          className="grow"
          type="password"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder="NEXUS_API_TOKEN"
        />
      </div>

      <div className="bar">
        <button onClick={doOverview} disabled={busy}>Visão geral</button>
        <button onClick={doSubscribers} disabled={busy}>Assinantes</button>
        <button onClick={doDevices} disabled={busy}>Equipamentos</button>
        <button onClick={doOutages} disabled={busy}>Quedas</button>
        <button onClick={doEvents} disabled={busy}>Eventos</button>
        <button onClick={doHealth} disabled={busy}>Autodiagnóstico</button>
      </div>

      <div className="bar">
        <label>Assinante</label>
        <input
          style={{ width: 120 }}
          value={subId}
          onChange={(e) => setSubId(e.target.value)}
          placeholder="id"
        />
        <button onClick={doBlock} disabled={busy}>Bloquear</button>
        <button onClick={doUnblock} disabled={busy}>Desbloquear</button>
        <button onClick={doBillingDry} disabled={busy}>Cobrança (dry-run)</button>
        <button onClick={doCheckDevices} disabled={busy}>Checar equip.</button>
      </div>

      <main>
        <section className="panel">{renderResult(result)}</section>
        <aside className="logpanel">
          <h2>Log</h2>
          {log.length === 0 ? (
            <p className="muted">— sem atividade —</p>
          ) : (
            log.map((l, i) => <div key={i} className="logline">{l}</div>)
          )}
        </aside>
      </main>
    </div>
  );
}

function Card({ n, l, cls }: { n: number | string; l: string; cls?: string }) {
  return (
    <div className={`card ${cls || ""}`}>
      <div className="n">{n}</div>
      <div className="l">{l}</div>
    </div>
  );
}

function renderResult(result: Result) {
  if (!result) return <p className="muted">Conecte (URL + token) e use os botões acima.</p>;

  if (result.kind === "overview") {
    const d = result.data;
    return (
      <>
        <h2>Visão geral</h2>
        <div className="cards">
          <Card n={d.subscribers.total} l="Assinantes" />
          <Card n={d.subscribers.blocked} l="Bloqueados" cls={d.subscribers.blocked ? "bad" : ""} />
          <Card n={d.devices.online} l="Equip. online" cls="ok" />
          <Card n={d.devices.offline} l="Equip. offline" cls={d.devices.offline ? "bad" : ""} />
          <Card n={d.open_outages.length} l="Quedas abertas" cls={d.open_outages.length ? "bad" : ""} />
          <Card n={d.blocked_count} l="IPs bloqueados" cls={d.blocked_count ? "warn" : ""} />
          <Card n={d.events_24h} l="Eventos 24h" />
          <Card n={d.pending_actions} l="Ações pendentes" cls={d.pending_actions ? "warn" : ""} />
        </div>
      </>
    );
  }

  if (result.kind === "subscribers") {
    return (
      <Table
        title={`Assinantes (${result.rows.length})`}
        cols={["id", "nome", "ip", "conexão", "fatura", "atraso"]}
        rows={result.rows.map((s) => [
          s.id, s.name, s.ip, s.status, s.invoice_status, `${s.days_overdue}d`,
        ])}
      />
    );
  }
  if (result.kind === "devices") {
    return (
      <Table
        title={`Equipamentos (${result.rows.length})`}
        cols={["id", "nome", "ip", "tipo", "estado"]}
        rows={result.rows.map((d) => [d.id, d.name, d.ip, d.type, d.status])}
      />
    );
  }
  if (result.kind === "outages") {
    return (
      <Table
        title={`Quedas abertas (${result.rows.length})`}
        cols={["equip.", "ip", "motivo", "desde"]}
        rows={result.rows.map((o) => [o.name, o.ip, o.reason, o.opened_at])}
      />
    );
  }
  if (result.kind === "events") {
    return (
      <Table
        title={`Eventos 24h (${result.rows.length})`}
        cols={["hora", "tipo", "ip", "detalhe"]}
        rows={result.rows.map((e) => [e.time, e.type, e.ip, e.detail])}
      />
    );
  }
  if (result.kind === "health") {
    return (
      <>
        <h2>Autodiagnóstico</h2>
        <pre className="mono">{result.text}</pre>
      </>
    );
  }
  // message
  return (
    <>
      <h2>{result.title}</h2>
      <pre className="mono">{result.text}</pre>
    </>
  );
}

function Table({ title, cols, rows }: { title: string; cols: string[]; rows: any[][] }) {
  return (
    <>
      <h2>{title}</h2>
      {rows.length === 0 ? (
        <p className="muted">— nada —</p>
      ) : (
        <table>
          <thead>
            <tr>{cols.map((c) => <th key={c}>{c}</th>)}</tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i}>{r.map((c, j) => <td key={j}>{String(c ?? "")}</td>)}</tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
