// Estado de AMBIENTE da interface — conceito puramente de frontend (não toca o
// backend). Define em qual "modo" o operador está visualizando:
//
//   real    — usa exclusivamente os dados reais retornados pela API.
//   lab     — demonstração visual de UX; qualquer conteúdo sem origem na API
//             aparece marcado como "Simulação visual / Demo local". Métricas
//             reais continuam reais e rotuladas; nada é misturado sem sinalização.
//   replay  — reprodução de eventos passados; indisponível na API atual
//             (preparado conceitualmente, sem backend novo nem dado simulado).
//
// A escolha é persistida em localStorage e NUNCA fabrica telemetria como se
// fosse real — apenas muda como a ausência/origem dos dados é apresentada.

import { createContext, useCallback, useContext, useState, type ReactNode } from "react";

export type EnvMode = "real" | "lab" | "replay";

export interface EnvCtx {
  mode: EnvMode;
  setMode: (m: EnvMode) => void;
}

const Ctx = createContext<EnvCtx | null>(null);
const KEY = "nexus_env_mode";

function initialMode(): EnvMode {
  const v = localStorage.getItem(KEY);
  return v === "lab" || v === "replay" ? v : "real";
}

export function useEnvironment(): EnvCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error("useEnvironment deve ser usado dentro de <EnvironmentProvider>");
  return c;
}

export function EnvironmentProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<EnvMode>(initialMode);
  const setMode = useCallback((m: EnvMode) => {
    localStorage.setItem(KEY, m);
    setModeState(m);
  }, []);
  return <Ctx.Provider value={{ mode, setMode }}>{children}</Ctx.Provider>;
}

export const MODE_LABEL: Record<EnvMode, string> = {
  real: "Real",
  lab: "Laboratório",
  replay: "Replay",
};

export const MODE_DESC: Record<EnvMode, string> = {
  real: "Usa exclusivamente dados reais retornados pela API.",
  lab: "Demonstração visual de UX. Conteúdo sem origem na API é marcado como “Simulação visual / Demo local”; métricas reais continuam reais.",
  replay: "Reprodução de eventos passados — indisponível na API atual.",
};
