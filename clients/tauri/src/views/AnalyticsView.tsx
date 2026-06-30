import { Activity, BarChart3, Ban, Bug } from "lucide-react";
import { Gate } from "./_gate";
import { MetricCard } from "../components/MetricCard";
import { DataPanel } from "../components/DataPanel";
import { EmptyState } from "../components/states";
import { HardwareEmptyState } from "../components/HardwareEmptyState";

export function AnalyticsView() {
  return (
    <Gate>
      {(d) => {
        const top = d.event_top || [];
        const max = Math.max(1, ...top.map(([, n]) => n));
        return (
          <div className="grid" style={{ gap: 16 }}>
            <div className="grid metrics">
              <MetricCard label="Eventos 24h" value={d.events_24h} icon={Activity} tone="info" />
              <MetricCard label="Tipos distintos" value={top.length} icon={BarChart3} />
              <MetricCard label="IPs bloqueados" value={d.blocked_count} icon={Ban} tone={d.blocked_count ? "warn" : "neutral"} />
              <MetricCard label="Honeypots ativos" value={d.honeypots.length} icon={Bug} tone={d.honeypots.length ? "ok" : "neutral"} />
            </div>
            <DataPanel title="Top tipos de evento (24h)" icon={BarChart3}>
              {top.length === 0 ? (
                d.events_24h === 0 && d.devices.total === 0 ? (
                  <HardwareEmptyState
                    icon={BarChart3}
                    title="Sem dados analíticos ainda"
                    hint="Não há eventos nas últimas 24h e nenhum hardware monitorado. Os gráficos serão preenchidos com telemetria real assim que houver eventos ou equipamentos conectados — nada é simulado."
                  />
                ) : (
                  <EmptyState title="Sem eventos" hint="Nada registrado nas últimas 24h." />
                )
              ) : (
                <div>
                  {top.map(([t, n]) => (
                    <div key={t} style={{ margin: "9px 0" }}>
                      <div className="row" style={{ justifyContent: "space-between", fontSize: 12.5 }}>
                        <span>{t}</span>
                        <span className="text-mut">{n}</span>
                      </div>
                      <div style={{ height: 8, background: "#0d1622", borderRadius: 6, overflow: "hidden", marginTop: 4 }}>
                        <div style={{ height: "100%", width: `${(n / max) * 100}%`, background: "linear-gradient(90deg,#1d6fa6,#38bdf8)" }} />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </DataPanel>
          </div>
        );
      }}
    </Gate>
  );
}
