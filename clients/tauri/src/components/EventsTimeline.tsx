import type { Overview, Severity } from "../lib/format";
import { relativeTime, severityOf } from "../lib/format";
import { EmptyState } from "./states";

function sevLabel(s: Severity): string {
  return s === "bad" ? "crítico" : s === "warn" ? "atenção" : s === "ok" ? "ok" : "info";
}

export function EventsTimeline({
  events, limit = 16,
}: { events: Overview["recent_events"]; limit?: number }) {
  if (!events.length) {
    return <EmptyState title="Sem eventos recentes" hint="Nada registrado na janela atual." />;
  }
  return (
    <div className="timeline">
      {events.slice(0, limit).map((e, i) => {
        const sev = severityOf(e.type);
        return (
          <div className="tl-item" key={i}>
            <div className="tl-rail"><span className={`tl-dot ${sev}`} /></div>
            <div className="tl-main">
              <div className="tl-type">
                {e.type} <span className={`sev-tag ${sev}`}>{sevLabel(sev)}</span>
              </div>
              <div className="tl-detail">{e.detail || "—"}</div>
            </div>
            <div className="tl-meta">
              {relativeTime(e.time)}
              {e.ip ? <><br /><span className="ip">{e.ip}</span></> : null}
            </div>
          </div>
        );
      })}
    </div>
  );
}
