import { Activity } from "lucide-react";
import { DataPanel } from "./DataPanel";
import { OperationalReadinessChecklist } from "./OperationalReadinessChecklist";
import { useNexus } from "../lib/useNexus";
import { useEnvironment, MODE_DESC, MODE_LABEL } from "../lib/environment";
import { computeReadiness } from "../lib/readiness";

// Painel "Estado do Ambiente" — discreto e profissional, mostra a prontidão
// operacional real (API, fonte, laboratório físico, hardware, mapa, replay).
// Comunica que esta é uma fase normal de implantação, não um erro.
export function LabReadinessPanel() {
  const { data, status } = useNexus();
  const { mode } = useEnvironment();
  const items = computeReadiness(data, status, mode);

  return (
    <DataPanel title="Estado do Ambiente" icon={Activity}>
      <OperationalReadinessChecklist items={items} />
      <div className="muted-note" style={{ marginTop: 10 }}>
        Modo atual: <strong>{MODE_LABEL[mode]}</strong> — {MODE_DESC[mode]} A interface está
        pronta para conectar hardware real no futuro, sem exibir telemetria inexistente.
      </div>
    </DataPanel>
  );
}
