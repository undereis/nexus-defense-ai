import { useState } from "react";
import { Activity, Ban, Receipt, RefreshCw, RotateCcw } from "lucide-react";
import { useNexus } from "../lib/useNexus";

export function QuickActions() {
  const { refresh, runAction, actionBusy } = useNexus();
  const [msg, setMsg] = useState<string | null>(null);
  const running = actionBusy !== null;

  async function billing() {
    try {
      const r: any = await runAction("billing", (a) => a.runBilling(true));
      setMsg(r?.message || "ok");
    } catch (e: any) {
      setMsg("Erro: " + (e?.message || e));
    }
  }

  async function check() {
    try {
      const r: any = await runAction("devices", (a) => a.checkDevices());
      const t: string[] = r?.transitions || [];
      setMsg(t.length ? `Transições: ${t.join("; ")}` : "Checagem concluída — sem transições.");
    } catch (e: any) {
      setMsg("Erro: " + (e?.message || e));
    }
  }

  return (
    <div>
      <div className="row">
        <button onClick={refresh} disabled={running}>
          <RefreshCw size={14} /> Atualizar dados
        </button>
        <button onClick={billing} disabled={running}>
          <Receipt size={14} /> Rodar billing (dry-run)
        </button>
        <button onClick={check} disabled={running}>
          <Activity size={14} /> Verificar dispositivos
        </button>
      </div>
      <div className="row" style={{ marginTop: 8 }}>
        <button disabled title="Sem endpoint na API atual">
          <Ban size={14} /> Bloquear ASN <span className="sev-tag">indisponível</span>
        </button>
        <button disabled title="Sem endpoint na API atual">
          <RotateCcw size={14} /> Reconciliar firewall <span className="sev-tag">indisponível</span>
        </button>
      </div>
      {msg ? (
        <div className="mono-box" style={{ marginTop: 10 }}>{msg}</div>
      ) : (
        <div className="muted-note" style={{ marginTop: 10 }}>
          Ações seguras: o billing roda em <strong>dry-run</strong> (não altera nada). Itens
          marcados como “indisponível” não existem na API atual — nada é simulado.
        </div>
      )}
    </div>
  );
}
