import { Radar } from "lucide-react";
import type { Overview } from "../lib/format";
import { classifyIp } from "../lib/format";
import { EmptyState } from "./states";

// Posição esquemática determinística a partir do IP (hash). Os IPs são REAIS
// (vêm de blocked_ips); só a posição no mapa é ilustrativa.
function hashPos(ip: string): { x: number; y: number } {
  let h = 0;
  for (let i = 0; i < ip.length; i++) h = (h * 31 + ip.charCodeAt(i)) >>> 0;
  return { x: 8 + (h % 84), y: 12 + ((h >> 8) % 74) };
}

export function ThreatMapPlaceholder({ data }: { data: Overview }) {
  const nodes = data.blocked_ips.slice(0, 14);
  return (
    <div className="threatmap">
      <span className="pill info ph-badge">visualização ilustrativa</span>
      <div className="tm-core"><Radar size={22} /></div>
      {nodes.length === 0 ? (
        <div style={{ position: "absolute", inset: 0, display: "grid", placeItems: "center" }}>
          <EmptyState title="Nenhuma ameaça plotada" hint="Sem IPs bloqueados nos dados atuais." />
        </div>
      ) : (
        nodes.map((b) => {
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
        })
      )}
    </div>
  );
}
