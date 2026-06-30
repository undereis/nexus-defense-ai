// "Estado do Ambiente" — derivação PURA do que a interface sabe hoje, a partir
// dos dados REAIS da API (devices.total, offline, etc.) + estado da conexão +
// modo de ambiente. Não inventa nada: traduz a realidade ("hardware ausente",
// "mapa ilustrativo", "replay indisponível") numa checklist honesta de prontidão.

import type { Overview, Severity } from "./format";
import type { ConnStatus } from "./useNexus";
import type { EnvMode } from "./environment";

export type ReadyState = Severity | "neutral";

export interface ReadinessItem {
  id: string;
  label: string;
  value: string;
  state: ReadyState;
  hint?: string;
}

function apiReadiness(status: ConnStatus): ReadinessItem {
  switch (status) {
    case "ok":
      return { id: "api", label: "API", value: "online", state: "ok" };
    case "offline":
      return { id: "api", label: "API", value: "offline", state: "bad", hint: "motor Python inacessível" };
    case "unauthorized":
      return { id: "api", label: "API", value: "token inválido", state: "bad", hint: "HTTP 401" };
    case "loading":
      return { id: "api", label: "API", value: "conectando…", state: "info" };
    default:
      return { id: "api", label: "API", value: "não configurado", state: "neutral" };
  }
}

export function computeReadiness(
  data: Overview | null,
  status: ConnStatus,
  mode: EnvMode,
): ReadinessItem[] {
  const items: ReadinessItem[] = [apiReadiness(status)];

  // Fonte dos dados — depende do modo, sinalizando origem com honestidade.
  if (mode === "lab") {
    items.push({
      id: "fonte", label: "Fonte", value: "visualização ilustrativa (demo local)", state: "warn",
      hint: "métricas reais da API permanecem reais e rotuladas",
    });
  } else if (mode === "replay") {
    items.push({ id: "fonte", label: "Fonte", value: "replay — indisponível na API atual", state: "neutral" });
  } else {
    items.push({
      id: "fonte", label: "Fonte",
      value: status === "ok" ? "dados reais da API" : "sem fonte de dados",
      state: status === "ok" ? "ok" : "neutral",
    });
  }

  const devTotal = data?.devices.total ?? 0;
  const devOffline = data?.devices.offline ?? 0;

  // Laboratório físico — proxy honesto: inventário de equipamentos cadastrados.
  items.push({
    id: "lab", label: "Laboratório físico",
    value: devTotal === 0 ? "não conectado / pendente" : "instância em operação",
    state: devTotal === 0 ? "warn" : "ok",
    hint: devTotal === 0 ? "nenhum equipamento cadastrado para monitoração" : undefined,
  });

  // Hardware monitorado.
  items.push({
    id: "hw", label: "Hardware monitorado",
    value: devTotal === 0 ? "ausente"
      : devOffline > 0 ? `parcial — ${devOffline}/${devTotal} offline`
        : `${devTotal} dispositivo(s)`,
    state: devTotal === 0 ? "neutral" : devOffline > 0 ? "bad" : "ok",
  });

  // Mapa — sempre ilustrativo enquanto não houver GeoIP na API.
  items.push({ id: "mapa", label: "Mapa", value: "ilustrativo (sem GeoIP na API)", state: "info" });

  // Replay — conceitual, sem endpoint hoje.
  items.push({ id: "replay", label: "Replay", value: "indisponível na API atual", state: "neutral" });

  return items;
}
