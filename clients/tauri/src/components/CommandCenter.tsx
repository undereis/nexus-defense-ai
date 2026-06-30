import { ShieldAlert } from "lucide-react";
import type { Overview } from "../lib/format";
import { riskLevel } from "../lib/format";
import { StatusPill } from "./StatusPill";

export function CommandCenter({ data }: { data: Overview }) {
  const risk = riskLevel(data);
  return (
    <div>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <div className="row">
          <ShieldAlert size={18} style={{ color: "var(--info)" }} />
          <strong>Estado operacional</strong>
        </div>
        <StatusPill tone={risk.level} label={`Risco: ${risk.label}`} />
      </div>
      <ul style={{ margin: "10px 0 0", paddingLeft: 18, color: "var(--fg-2)", fontSize: 13 }}>
        {risk.reasons.map((r, i) => <li key={i}>{r}</li>)}
      </ul>
    </div>
  );
}
