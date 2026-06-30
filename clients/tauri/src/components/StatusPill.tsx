import type { Severity } from "../lib/format";

export function StatusPill({ tone, label }: { tone: Severity | "neutral"; label: string }) {
  return (
    <span className={`pill ${tone === "neutral" ? "" : tone}`}>
      <span className="dot" />
      {label}
    </span>
  );
}
