import { PlugZap, type LucideIcon } from "lucide-react";

// Empty state profissional para seções que dependem de hardware/laboratório
// ainda não conectado. Comunica "fase normal de implantação", não erro.
export function HardwareEmptyState({
  icon: Icon = PlugZap,
  title = "Aguardando laboratório / hardware",
  hint,
}: { icon?: LucideIcon; title?: string; hint?: string }) {
  return (
    <div className="state hw-empty">
      <div className="hw-empty-ico"><Icon /></div>
      <h3>{title}</h3>
      {hint ? <p>{hint}</p> : null}
      <span className="pill info" style={{ marginTop: 6 }}>
        <span className="dot" /> pronto para conexão futura
      </span>
    </div>
  );
}
