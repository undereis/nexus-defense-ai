import { useCallback, useEffect, useState } from "react";
import { Brain, RefreshCw, Stethoscope } from "lucide-react";
import { useNexus } from "../lib/useNexus";
import { Gate } from "./_gate";
import { DataPanel } from "../components/DataPanel";
import { NexusInsights } from "../components/NexusInsights";
import { ErrorState, Skeleton } from "../components/states";

export function IAView() {
  const { api } = useNexus();
  const [report, setReport] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    setErr(null);
    try {
      const d: any = await api().health();
      setReport(d.report || "");
    } catch (e: any) {
      setErr(e?.message || String(e));
    }
  }, [api]);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="grid cols-main">
      <DataPanel title="Nexus IA — Insights" icon={Brain}>
        <Gate>{(d) => <NexusInsights data={d} />}</Gate>
      </DataPanel>
      <DataPanel
        title="Autodiagnóstico (API /api/health)"
        icon={Stethoscope}
        actions={<button onClick={load}><RefreshCw size={14} /> Atualizar</button>}
      >
        {err ? (
          <ErrorState kind="offline" message={err} onRetry={load} />
        ) : report === null ? (
          <Skeleton lines={8} />
        ) : (
          <div className="mono-box">{report}</div>
        )}
      </DataPanel>
    </div>
  );
}
