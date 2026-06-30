import {
  LayoutDashboard, Shield, Map, Router, Flame, Brain,
  BarChart3, Crosshair, ScrollText, Settings, type LucideIcon,
} from "lucide-react";

export interface NavItem {
  id: string;
  label: string;
  icon: LucideIcon;
  tag?: string; // ex.: "ilustr." (visual) ou "—" (sem dados na API atual)
}

// Itens da sidebar. Só "dashboard"/"defesa"/"firewall"/"ia"/"analytics"/"ti"/
// "logs"/"config" têm dados reais na API atual; "mapa" é visualização
// ilustrativa e "mikrotik" não tem endpoint REST hoje (marcado honestamente).
export const NAV: NavItem[] = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "defesa", label: "Defesa", icon: Shield },
  { id: "mapa", label: "Mapa", icon: Map, tag: "ilustr." },
  { id: "mikrotik", label: "Mikrotik", icon: Router, tag: "—" },
  { id: "firewall", label: "Firewall", icon: Flame },
  { id: "ia", label: "IA", icon: Brain },
  { id: "analytics", label: "Analytics", icon: BarChart3 },
  { id: "ti", label: "Threat Intelligence", icon: Crosshair },
  { id: "logs", label: "Logs", icon: ScrollText },
  { id: "config", label: "Configurações", icon: Settings },
];
