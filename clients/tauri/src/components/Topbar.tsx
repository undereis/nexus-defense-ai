import { RefreshCw } from "lucide-react";
import { useNexus, isStale } from "../lib/useNexus";
import { relativeTime, type Severity } from "../lib/format";
import { StatusPill } from "./StatusPill";
import { EnvironmentModePill } from "./EnvironmentModePill";

export function Topbar({ title }: { title: string }) {
  const { status, lastUpdated, busy, refresh } = useNexus();

  const tone: Severity | "neutral" =
    status === "ok" ? "ok"
      : status === "unauthorized" || status === "offline" ? "bad"
        : status === "loading" ? "info"
          : "neutral";
  const label =
    status === "ok" ? "API online"
      : status === "unauthorized" ? "token inválido"
        : status === "offline" ? "API offline"
          : status === "loading" ? "conectando…"
            : "não configurado";

  const stale = isStale(lastUpdated);

  return (
    <header className="topbar">
      <h2>{title}</h2>
      <StatusPill tone={tone} label={label} />
      <span className="spacer" />
      <EnvironmentModePill />
      <span className={`updated ${stale ? "stale" : ""}`}>
        {lastUpdated
          ? `atualizado ${relativeTime(lastUpdated.toISOString())}${stale ? " · possivelmente vencido" : ""}`
          : "sem dados ainda"}
      </span>
      <button className="icon-btn" onClick={refresh} disabled={busy} title="Atualizar">
        <RefreshCw size={15} className={busy ? "spin" : ""} />
        Atualizar
      </button>
    </header>
  );
}
