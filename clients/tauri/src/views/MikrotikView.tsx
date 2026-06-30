import { Router } from "lucide-react";
import { DataPanel } from "../components/DataPanel";
import { HardwareEmptyState } from "../components/HardwareEmptyState";

export function MikrotikView() {
  return (
    <DataPanel title="Mikrotik / RouterOS" icon={Router}>
      <HardwareEmptyState
        icon={Router}
        title="Aguardando laboratório / hardware"
        hint="A API REST atual não expõe endpoints de Mikrotik/RouterOS e ainda não há equipamento conectado. O motor Python já possui as tools de RouterOS; esta seção será ativada quando os endpoints existirem na superfície /api/* e o hardware estiver na rede. Nada é simulado aqui."
      />
    </DataPanel>
  );
}
