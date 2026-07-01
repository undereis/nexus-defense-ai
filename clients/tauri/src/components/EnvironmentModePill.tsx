import { useEffect } from "react";
import { Radio, FlaskConical, History, type LucideIcon } from "lucide-react";
import { useEnvironment, MODE_DESC, type EnvMode } from "../lib/environment";
import { useNexus } from "../lib/useNexus";

const OPTS: { mode: EnvMode; label: string; icon: LucideIcon }[] = [
  { mode: "real", label: "Real", icon: Radio },
  { mode: "lab", label: "Lab", icon: FlaskConical },
  { mode: "replay", label: "Replay", icon: History },
];

// Seletor de modo (Real / Laboratório / Replay), na Topbar.
//
// Fase 4 — sincronizado com o MOTOR: quando o backend está online, o pill puxa o
// modo operacional efetivo (GET /api/mode) e, ao clicar, PROPÕE a troca (POST
// /api/mode; gated por RBAC — só admin). A UI reflete o que o motor de fato
// aceitou (não fabrica). Offline, cai para o modo apenas-visual (localStorage).
export function EnvironmentModePill() {
  const { mode, setMode, backendMode, backendSynced, modeError, reportBackend } = useEnvironment();
  const { api, status, configured } = useNexus();

  // Puxa o modo efetivo do motor ao (re)conectar.
  useEffect(() => {
    if (!configured || status !== "ok") {
      reportBackend(null);
      return;
    }
    let cancelled = false;
    api()
      .getMode()
      .then((r: any) => { if (!cancelled) reportBackend(r.mode as EnvMode); })
      .catch(() => { if (!cancelled) reportBackend(null, "motor inacessível"); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [configured, status]);

  async function choose(m: EnvMode) {
    if (m === mode && backendSynced) return;
    // Offline / sem config: modo apenas visual (comportamento anterior).
    if (!configured || status !== "ok") {
      setMode(m);
      reportBackend(null, "motor offline — modo apenas visual");
      return;
    }
    // Online: propõe ao motor e reflete o modo efetivo aceito.
    try {
      const r: any = await api().setMode(m);
      reportBackend(r.mode as EnvMode);
    } catch (e: any) {
      const msg = e?.message || String(e);
      reportBackend(
        backendMode,
        msg.includes("403") ? "sem permissão para trocar o modo do motor" : msg.slice(0, 120),
      );
    }
  }

  const hint = modeError
    ? modeError
    : backendSynced
      ? "Sincronizado com o modo operacional do motor (backend)."
      : "Modo apenas visual — não sincronizado com o motor.";

  return (
    <div
      className="mode-seg"
      role="group"
      aria-label="Modo do ambiente"
      data-synced={backendSynced ? "1" : "0"}
      data-error={modeError ? "1" : "0"}
      title={hint}
    >
      {OPTS.map((o) => {
        const Icon = o.icon;
        return (
          <button
            key={o.mode}
            type="button"
            className={`mode-opt ${o.mode} ${mode === o.mode ? "active" : ""}`}
            onClick={() => choose(o.mode)}
            title={MODE_DESC[o.mode]}
          >
            <Icon size={13} /> {o.label}
          </button>
        );
      })}
    </div>
  );
}
