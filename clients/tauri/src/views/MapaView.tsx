import { Radar } from "lucide-react";
import { Gate } from "./_gate";
import { DataPanel } from "../components/DataPanel";
import { ThreatMapPlaceholder } from "../components/ThreatMapPlaceholder";
import { useEnvironment } from "../lib/environment";

export function MapaView() {
  const { mode } = useEnvironment();
  return (
    <Gate>
      {(d) => (
        <DataPanel title="Mapa de Ameaças" icon={Radar}>
          <ThreatMapPlaceholder data={d} />
          <div className="muted-note" style={{ marginTop: 10 }}>
            {mode === "lab"
              ? "Modo Laboratório: além dos IPs reais (quando houver), são exibidos nós de demonstração marcados como “Simulação visual / demo local”. Nenhum IP, país ou cidade é inventado."
              : mode === "replay"
                ? "Modo Replay: reprodução de eventos indisponível na API atual."
                : "Visualização ilustrativa: as posições são esquemáticas. Os IPs plotados são REAIS (blocklist da API). Não há backend de geolocalização — quando a API expuser dados de GeoIP, o mapa passará a usá-los. Nada é simulado como se fosse real."}
          </div>
        </DataPanel>
      )}
    </Gate>
  );
}
