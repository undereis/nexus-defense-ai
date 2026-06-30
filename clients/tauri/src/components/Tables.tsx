import { AlertOctagon } from "lucide-react";
import type { Overview } from "../lib/format";
import { classifyIp, relativeTime } from "../lib/format";
import { EmptyState } from "./states";

export function BlockedIpsTable({ rows, limit = 50 }: { rows: Overview["blocked_ips"]; limit?: number }) {
  if (!rows.length) return <EmptyState title="Nenhum IP bloqueado" hint="A blocklist está vazia nos dados atuais." />;
  return (
    <table>
      <thead><tr><th>IP</th><th>desde</th><th>motivo</th></tr></thead>
      <tbody>
        {rows.slice(0, limit).map((b) => {
          const flag = classifyIp(b.ip);
          return (
            <tr key={b.ip}>
              <td className="ipcell">
                {b.ip}{" "}
                {flag.suspicious ? (
                  <span className="sev-tag bad" title={flag.reason}>
                    <AlertOctagon size={10} style={{ verticalAlign: "-1px" }} /> inconsistente
                  </span>
                ) : null}
              </td>
              <td>{relativeTime(b.since)}</td>
              <td>{b.reason || "—"}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

export function OutagesTable({ rows }: { rows: Overview["open_outages"] }) {
  if (!rows.length) return <EmptyState title="Nenhuma queda aberta" hint="Todos os equipamentos monitorados estão de pé." />;
  return (
    <table>
      <thead><tr><th>equipamento</th><th>IP</th><th>motivo</th><th>desde</th></tr></thead>
      <tbody>
        {rows.map((o) => (
          <tr key={o.device_id}>
            <td>{o.name || o.device_id}</td>
            <td className="ipcell">{o.ip}</td>
            <td>{o.reason || "—"}</td>
            <td>{relativeTime(o.since)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
