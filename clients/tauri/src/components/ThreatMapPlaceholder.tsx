import { Radar } from "lucide-react";
import type { Overview } from "../lib/format";
import { classifyIp } from "../lib/format";
import { useEnvironment } from "../lib/environment";
import { EmptyState } from "./states";
import { SimulationNotice } from "./SimulationNotice";

// Posição esquemática determinística a partir de uma semente (hash). Para nós
// reais a semente é o IP REAL (vindo de blocked_ips); só a posição é ilustrativa.
function hashPos(seed: string): { x: number; y: number } {
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
  return { x: 8 + (h % 84), y: 12 + ((h >> 8) % 74) };
}

// Nós de demonstração (modo Laboratório): anônimos, SEM IP/país/cidade falsos —
// só ilustram a aparência do mapa quando houver sensores.
const DEMO_NODES = ["sensor-a", "sensor-b", "sensor-c", "sensor-d", "sensor-e", "sensor-f"];

export function ThreatMapPlaceholder({ data }: { data: Overview }) {
  const { mode } = useEnvironment();
  const real = data.blocked_ips.slice(0, 14);

  // Replay: conceitual, sem dados na API.
  if (mode === "replay") {
    return (
      <div className="threatmap">
        <div style={{ position: "absolute", inset: 0, display: "grid", placeItems: "center", padding: 16 }}>
          <EmptyState
            icon={Radar}
            title="Replay indisponível na API atual"
            hint="A reprodução de eventos será habilitada quando a API expuser dados de replay. Nada é simulado."
          />
        </div>
      </div>
    );
  }

  // Real sem IPs: empty state profissional (sem inventar ameaça).
  if (mode === "real" && real.length === 0) {
    return (
      <div className="threatmap">
        <div className="tm-core"><Radar size={22} /></div>
        <div style={{ position: "absolute", inset: 0, display: "grid", placeItems: "center", padding: 16 }}>
          <EmptyState
            icon={Radar}
            title="Nenhum dado de ameaça real disponível ainda"
            hint="Conecte sensores/laboratório ou aguarde eventos reais. Nenhum IP, país ou ataque é inventado."
          />
        </div>
      </div>
    );
  }

  const showDemo = mode === "lab";
  return (
    <div className="threatmap">
      <span className={`pill ${showDemo ? "warn" : "info"} ph-badge`}>
        {showDemo ? "simulação visual" : "dados reais da API"}
      </span>
      <div className="tm-core"><Radar size={22} /></div>

      {/* nós reais — IPs reais da blocklist */}
      {real.map((b) => {
        const p = hashPos(b.ip);
        const susp = classifyIp(b.ip).suspicious;
        return (
          <div
            className="tm-node"
            style={{ left: `${p.x}%`, top: `${p.y}%` }}
            key={b.ip}
            title={`${b.ip} — ${b.reason || ""}`}
          >
            <span className={`tm-blip ring ${susp ? "warn" : ""}`} />
            <span>{b.ip}</span>
          </div>
        );
      })}

      {/* nós de demonstração — só no modo Laboratório, anônimos e rotulados */}
      {showDemo && DEMO_NODES.map((seed) => {
        const p = hashPos(seed);
        return (
          <div
            className="tm-node demo"
            style={{ left: `${p.x}%`, top: `${p.y}%` }}
            key={seed}
            title="nó ilustrativo (demo local) — sem dado real"
          >
            <span className="tm-blip ring demo" />
            <span className="demo-lbl">demo</span>
          </div>
        );
      })}

      {showDemo && (
        <div style={{ position: "absolute", left: 10, bottom: 10, zIndex: 3 }}>
          <SimulationNotice inline />
        </div>
      )}
    </div>
  );
}
