import { Radio, FlaskConical, History, type LucideIcon } from "lucide-react";
import { useEnvironment, MODE_DESC, type EnvMode } from "../lib/environment";

const OPTS: { mode: EnvMode; label: string; icon: LucideIcon }[] = [
  { mode: "real", label: "Real", icon: Radio },
  { mode: "lab", label: "Lab", icon: FlaskConical },
  { mode: "replay", label: "Replay", icon: History },
];

// Seletor de modo (Real / Laboratório / Replay) — controle segmentado global,
// vive na Topbar. Trocar o modo só muda a apresentação, nunca os dados reais.
export function EnvironmentModePill() {
  const { mode, setMode } = useEnvironment();
  return (
    <div className="mode-seg" role="group" aria-label="Modo do ambiente">
      {OPTS.map((o) => {
        const Icon = o.icon;
        return (
          <button
            key={o.mode}
            type="button"
            className={`mode-opt ${o.mode} ${mode === o.mode ? "active" : ""}`}
            onClick={() => setMode(o.mode)}
            title={MODE_DESC[o.mode]}
          >
            <Icon size={13} /> {o.label}
          </button>
        );
      })}
    </div>
  );
}
