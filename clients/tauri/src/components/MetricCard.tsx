import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import type { Severity } from "../lib/format";

export function MetricCard({
  label, value, hint, tone = "neutral", icon: Icon,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: Severity | "neutral";
  icon?: LucideIcon;
}) {
  return (
    <div className={`metric ${tone}`}>
      <div className="metric-top">
        <span className="metric-label">{label}</span>
        {Icon ? <Icon className="metric-ico" /> : null}
      </div>
      <div className="metric-value">{value}</div>
      {hint ? <div className="metric-hint">{hint}</div> : null}
    </div>
  );
}
