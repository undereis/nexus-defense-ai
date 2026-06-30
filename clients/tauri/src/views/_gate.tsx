import type { ReactNode } from "react";
import { useNexus } from "../lib/useNexus";
import type { Overview } from "../lib/format";
import { ErrorState, SkeletonCards } from "../components/states";

// Envolve uma view: trata 401, API offline (sem cache) e loading inicial.
// Se houver dados em cache mas a API caiu, ainda renderiza (a Topbar sinaliza
// "offline / possivelmente vencido") — não some com a tela do operador.
export function Gate({ children }: { children: (data: Overview) => ReactNode }) {
  const { data, status, error, refresh } = useNexus();
  if (status === "unauthorized") return <ErrorState kind="unauthorized" message={error || undefined} />;
  if (status === "offline" && !data) return <ErrorState kind="offline" message={error || undefined} onRetry={refresh} />;
  if (!data) return <SkeletonCards />;
  return <>{children(data)}</>;
}
