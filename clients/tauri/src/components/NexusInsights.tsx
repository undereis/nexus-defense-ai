import { AlertOctagon, AlertTriangle, CheckCircle2, Info, type LucideIcon } from "lucide-react";
import type { Overview, Severity } from "../lib/format";
import { computeInsights, readinessInsights } from "../lib/insights";
import { useEnvironment } from "../lib/environment";

const ICON: Record<Severity, LucideIcon> = {
  bad: AlertOctagon,
  warn: AlertTriangle,
  ok: CheckCircle2,
  info: Info,
};

export function NexusInsights({ data }: { data: Overview }) {
  const { mode } = useEnvironment();
  // Achados/inconsistências reais primeiro; depois prontidão/preparação.
  const items = [...computeInsights(data), ...readinessInsights(data, mode)];
  return (
    <div>
      <div className="muted-note" style={{ marginBottom: 10 }}>
        Insights calculados no app a partir dos dados reais da API — sinalização,
        não executa nenhuma ação.
      </div>
      {items.map((it, i) => {
        const Icon = ICON[it.severity];
        return (
          <div className={`insight ${it.severity}`} key={i}>
            <Icon className="insight-ico" />
            <div>
              <div className="insight-title">{it.title}</div>
              <div className="insight-text">{it.text}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
