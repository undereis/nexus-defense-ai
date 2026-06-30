import {
  CheckCircle2, AlertTriangle, XCircle, Info, Circle, type LucideIcon,
} from "lucide-react";
import type { ReadinessItem, ReadyState } from "../lib/readiness";

const ICON: Record<ReadyState, LucideIcon> = {
  ok: CheckCircle2,
  warn: AlertTriangle,
  bad: XCircle,
  info: Info,
  neutral: Circle,
};

// Renderiza a checklist de prontidão operacional (label · valor · estado).
// Presentational puro — recebe os itens já derivados em lib/readiness.
export function OperationalReadinessChecklist({ items }: { items: ReadinessItem[] }) {
  return (
    <div className="readiness">
      {items.map((it) => {
        const Icon = ICON[it.state];
        return (
          <div className={`ready-row ${it.state}`} key={it.id}>
            <Icon className="ready-ico" size={15} />
            <span className="ready-label">{it.label}</span>
            <span className="ready-value">{it.value}</span>
            {it.hint ? <span className="ready-hint">{it.hint}</span> : null}
          </div>
        );
      })}
    </div>
  );
}
