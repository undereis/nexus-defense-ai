import { AlertOctagon, Ban, Flame, UserCog } from "lucide-react";
import { Gate } from "./_gate";
import { MetricCard } from "../components/MetricCard";
import { DataPanel } from "../components/DataPanel";
import { BlockedIpsTable } from "../components/Tables";
import { SubscriberAction } from "../components/SubscriberAction";
import { classifyIp } from "../lib/format";

export function FirewallView() {
  return (
    <Gate>
      {(d) => {
        const susp = d.blocked_ips.filter((b) => classifyIp(b.ip).suspicious);
        return (
          <div className="grid" style={{ gap: 16 }}>
            <div className="grid metrics">
              <MetricCard label="IPs bloqueados" value={d.blocked_count} icon={Ban} tone={d.blocked_count ? "warn" : "neutral"} />
              <MetricCard
                label="Inconsistentes"
                value={susp.length}
                icon={AlertOctagon}
                tone={susp.length ? "bad" : "ok"}
                hint={susp.length ? "IPs internos/loopback na blocklist" : "nenhum"}
              />
            </div>
            <DataPanel title="Blocklist (firewall)" icon={Flame} tight>
              <BlockedIpsTable rows={d.blocked_ips} />
            </DataPanel>
            <DataPanel title="Bloquear / desbloquear assinante" icon={UserCog}>
              <SubscriberAction />
            </DataPanel>
          </div>
        );
      }}
    </Gate>
  );
}
