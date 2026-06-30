import {
  Activity, Ban, Brain, Flame, Radar, ScrollText, ServerCog, ServerCrash,
  ShieldCheck, Siren, UserX, Users, Zap,
} from "lucide-react";
import { Gate } from "./_gate";
import { MetricCard } from "../components/MetricCard";
import { DataPanel } from "../components/DataPanel";
import { ThreatMapPlaceholder } from "../components/ThreatMapPlaceholder";
import { CommandCenter } from "../components/CommandCenter";
import { NexusInsights } from "../components/NexusInsights";
import { QuickActions } from "../components/QuickActions";
import { EventsTimeline } from "../components/EventsTimeline";
import { BlockedIpsTable, OutagesTable } from "../components/Tables";
import { LabReadinessPanel } from "../components/LabReadinessPanel";
import { useEnvironment } from "../lib/environment";

export function DashboardView() {
  const { mode } = useEnvironment();
  return (
    <Gate>
      {(d) => (
        <div className="grid" style={{ gap: 16 }}>
          <div className="grid metrics">
            <MetricCard label="Sistema" value="Online" tone="ok" icon={ShieldCheck} hint="API respondendo" />
            <MetricCard label="Assinantes" value={d.subscribers.total} icon={Users} />
            <MetricCard label="Bloqueados" value={d.subscribers.blocked} icon={UserX} tone={d.subscribers.blocked ? "bad" : "neutral"} />
            <MetricCard label="Equip. online" value={`${d.devices.online}/${d.devices.total}`} icon={ServerCog} tone="ok" />
            <MetricCard label="Quedas abertas" value={d.open_outages.length} icon={Siren} tone={d.open_outages.length ? "bad" : "ok"} />
            <MetricCard label="IPs bloqueados" value={d.blocked_count} icon={Ban} tone={d.blocked_count ? "warn" : "neutral"} />
            <MetricCard label="Eventos 24h" value={d.events_24h} icon={Activity} tone="info" />
          </div>

          <LabReadinessPanel />

          <div className="grid cols-main">
            <div className="grid" style={{ gap: 16 }}>
              <DataPanel title="Mapa de Ameaças" icon={Radar}>
                <ThreatMapPlaceholder data={d} />
                <div className="muted-note" style={{ marginTop: 8 }}>
                  {mode === "lab"
                    ? "Modo Laboratório: nós de demonstração marcados como “Simulação visual”. IPs reais (blocklist da API) aparecem rotulados; nenhum IP/país é inventado."
                    : "Posições esquemáticas (sem GeoIP na API). Os IPs plotados são reais — da blocklist da API."}
                </div>
              </DataPanel>
              <DataPanel title="Centro de Operações" icon={Zap}>
                <CommandCenter data={d} />
              </DataPanel>
            </div>

            <div className="grid" style={{ gap: 16 }}>
              <DataPanel title="Nexus IA — Insights" icon={Brain}>
                <NexusInsights data={d} />
              </DataPanel>
              <DataPanel title="Ações rápidas" icon={Zap}>
                <QuickActions />
              </DataPanel>
            </div>
          </div>

          <div className="grid cols-2">
            <DataPanel title="Eventos recentes" icon={ScrollText} tight>
              <div style={{ padding: "2px 8px" }}>
                <EventsTimeline events={d.recent_events} />
              </div>
            </DataPanel>
            <div className="grid" style={{ gap: 16 }}>
              <DataPanel title="IPs bloqueados" icon={Flame} tight>
                <BlockedIpsTable rows={d.blocked_ips} limit={8} />
              </DataPanel>
              <DataPanel title="Quedas de equipamento" icon={ServerCrash} tight>
                <OutagesTable rows={d.open_outages} />
              </DataPanel>
            </div>
          </div>
        </div>
      )}
    </Gate>
  );
}
