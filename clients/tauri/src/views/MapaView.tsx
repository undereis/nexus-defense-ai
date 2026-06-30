import { Radar } from "lucide-react";
import { Gate } from "./_gate";
import { DataPanel } from "../components/DataPanel";
import { ThreatMapPlaceholder } from "../components/ThreatMapPlaceholder";

export function MapaView() {
  return (
    <Gate>
      {(d) => (
        <DataPanel title="Mapa de Ameaças" icon={Radar}>
          <ThreatMapPlaceholder data={d} />
          <div className="muted-note" style={{ marginTop: 10 }}>
            Visualização ilustrativa: as posições são esquemáticas. Os IPs plotados são
            REAIS (blocklist da API). Não há backend de geolocalização — quando a API expuser
            dados de GeoIP, o mapa passará a usá-los. Nada é simulado como se fosse real.
          </div>
        </DataPanel>
      )}
    </Gate>
  );
}
