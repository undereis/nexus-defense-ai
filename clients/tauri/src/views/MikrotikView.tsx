import { PlugZap, Router } from "lucide-react";
import { DataPanel } from "../components/DataPanel";
import { EmptyState } from "../components/states";

export function MikrotikView() {
  return (
    <DataPanel title="Mikrotik" icon={Router}>
      <EmptyState
        icon={PlugZap}
        title="Indisponível na API atual"
        hint="A API REST atual não expõe endpoints de Mikrotik/RouterOS. O motor Python tem as tools, mas elas não estão na superfície /api/*. Esta seção será ativada quando esses endpoints existirem — nada é simulado aqui."
      />
    </DataPanel>
  );
}
