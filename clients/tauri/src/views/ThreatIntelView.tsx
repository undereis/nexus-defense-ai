import { Brain, Crosshair, Siren } from "lucide-react";
import { Gate } from "./_gate";
import { DataPanel } from "../components/DataPanel";
import { BlockedIpsTable } from "../components/Tables";
import { EventsTimeline } from "../components/EventsTimeline";
import { NexusInsights } from "../components/NexusInsights";
import { severityOf } from "../lib/format";

export function ThreatIntelView() {
  return (
    <Gate>
      {(d) => {
        const threats = d.recent_events.filter((e) => ["bad", "warn"].includes(severityOf(e.type)));
        return (
          <div className="grid cols-2">
            <DataPanel title="IPs bloqueados (reputação)" icon={Crosshair} tight>
              <BlockedIpsTable rows={d.blocked_ips} />
            </DataPanel>
            <div className="grid" style={{ gap: 16 }}>
              <DataPanel title="Eventos de ameaça (recentes)" icon={Siren} tight>
                <div style={{ padding: "2px 8px" }}>
                  <EventsTimeline events={threats} limit={30} />
                </div>
              </DataPanel>
              <DataPanel title="Nexus IA — Insights" icon={Brain}>
                <NexusInsights data={d} />
              </DataPanel>
            </div>
          </div>
        );
      }}
    </Gate>
  );
}
