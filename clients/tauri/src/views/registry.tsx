import type { ComponentType } from "react";
import { DashboardView } from "./DashboardView";
import { DefesaView } from "./DefesaView";
import { MapaView } from "./MapaView";
import { MikrotikView } from "./MikrotikView";
import { FirewallView } from "./FirewallView";
import { IAView } from "./IAView";
import { AnalyticsView } from "./AnalyticsView";
import { ThreatIntelView } from "./ThreatIntelView";
import { LogsView } from "./LogsView";
import { SettingsView } from "./SettingsView";

export interface ViewEntry {
  title: string;
  Component: ComponentType;
}

// Mapa id (sidebar) -> view. Mantém o título exibido na topbar.
export const VIEWS: Record<string, ViewEntry> = {
  dashboard: { title: "Dashboard", Component: DashboardView },
  defesa: { title: "Defesa", Component: DefesaView },
  mapa: { title: "Mapa de Ameaças", Component: MapaView },
  mikrotik: { title: "Mikrotik", Component: MikrotikView },
  firewall: { title: "Firewall", Component: FirewallView },
  ia: { title: "Nexus IA", Component: IAView },
  analytics: { title: "Analytics", Component: AnalyticsView },
  ti: { title: "Threat Intelligence", Component: ThreatIntelView },
  logs: { title: "Logs", Component: LogsView },
  config: { title: "Configurações", Component: SettingsView },
};
