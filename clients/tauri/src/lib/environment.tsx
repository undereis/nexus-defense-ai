// Estado de AMBIENTE da interface. Define em qual "modo" o operador está:
//
//   real    — usa exclusivamente os dados reais retornados pela API.
//   lab     — demonstração visual de UX; qualquer conteúdo sem origem na API
//             aparece marcado como "Simulação visual / Demo local". Métricas
//             reais continuam reais e rotuladas; nada é misturado sem sinalização.
//   replay  — reprodução de eventos passados; indisponível na API atual
//             (preparado conceitualmente, sem backend novo nem dado simulado).
//
// Fase 4 — SINCRONIZAÇÃO com o motor: quando o backend está online, este modo
// reflete o MODO OPERACIONAL EFETIVO do motor (GET /api/mode), e trocá-lo pelo
// pill PROPÕE a mudança ao backend (POST /api/mode, gated por RBAC). Offline, cai
// para o modo apenas-visual persistido em localStorage. Em nenhum caso fabrica
// telemetria como se fosse real — só muda como a ausência/origem é apresentada.

import { createContext, useCallback, useContext, useState, type ReactNode } from "react";

export type EnvMode = "real" | "lab" | "replay";

export interface EnvCtx {
  mode: EnvMode;                 // modo EXIBIDO (== motor quando sincronizado)
  setMode: (m: EnvMode) => void; // define localmente (visual/otimista, offline)
  backendMode: EnvMode | null;   // modo do MOTOR reportado pela API (null = desconhecido)
  backendSynced: boolean;        // mode reflete o modo real do motor?
  modeError: string | null;      // erro da última troca de modo do motor (ex.: 403)
  reportBackend: (mode: EnvMode | null, error?: string | null) => void; // motor -> UI
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
  const [backendMode, setBackendMode] = useState<EnvMode | null>(null);
  const [modeError, setModeError] = useState<string | null>(null);

  const setMode = useCallback((m: EnvMode) => {
    localStorage.setItem(KEY, m);
    setModeState(m);
  }, []);

  // O motor reporta seu modo efetivo (ou null se inacessível). Quando conhecido,
  // a UI é ALINHADA a ele — o pill passa a mostrar a verdade do backend.
  const reportBackend = useCallback((bm: EnvMode | null, error: string | null = null) => {
    setBackendMode(bm);
    setModeError(error);
    if (bm) {
      localStorage.setItem(KEY, bm);
      setModeState(bm);
    }
  }, []);

  const backendSynced = backendMode !== null && backendMode === mode;

  return (
    <Ctx.Provider value={{ mode, setMode, backendMode, backendSynced, modeError, reportBackend }}>
      {children}
    </Ctx.Provider>
  );
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
