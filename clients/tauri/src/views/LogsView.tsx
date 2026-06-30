import { useCallback, useEffect, useState } from "react";
import { RefreshCw, ScrollText } from "lucide-react";
import { useNexus } from "../lib/useNexus";
import { DataPanel } from "../components/DataPanel";
import { EventsTimeline } from "../components/EventsTimeline";
import { ErrorState, Skeleton } from "../components/states";
import type { Overview } from "../lib/format";

export function LogsView() {
  const { api } = useNexus();
  const [hours, setHours] = useState(24);
  const [events, setEvents] = useState<Overview["recent_events"] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setErr(null);
    try {
      const d: any = await api().events(hours);
      setEvents(d.events || []);
    } catch (e: any) {
      setErr(e?.message || String(e));
      setEvents(null);
    } finally {
      setLoading(false);
    }
  }, [api, hours]);

  useEffect(() => { load(); }, [load]);

  return (
    <DataPanel
      title="Logs / Eventos"
      icon={ScrollText}
      tight
      actions={
        <div className="row">
          <select value={hours} onChange={(e) => setHours(Number(e.target.value))}>
            <option value={1}>1h</option>
            <option value={6}>6h</option>
            <option value={24}>24h</option>
            <option value={72}>72h</option>
            <option value={168}>7d</option>
          </select>
          <button onClick={load} disabled={loading}>
            <RefreshCw size={14} className={loading ? "spin" : ""} /> Recarregar
          </button>
        </div>
      }
    >
      {err ? (
        <ErrorState kind="offline" message={err} onRetry={load} />
      ) : events === null ? (
        <div style={{ padding: 12 }}><Skeleton lines={7} /></div>
      ) : (
        <div style={{ padding: "2px 8px" }}>
          <EventsTimeline events={events} limit={300} />
        </div>
      )}
    </DataPanel>
  );
}
