// Estado central do cliente: configuração (URL/token), busca do /api/overview
// com polling, e classificação de estado (ok / offline / token inválido).
// Reutiliza o cliente REST existente (../api) sem alterar suas chamadas.

import {
  createContext, useCallback, useContext, useEffect, useState, type ReactNode,
} from "react";
import { NexusApi } from "../api";
import type { Overview } from "./format";

export type ConnStatus = "idle" | "loading" | "ok" | "offline" | "unauthorized";

const POLL_MS = 15000;
const STALE_MS = 45000; // dados "possivelmente vencidos" após 45s sem refresh

export interface NexusCtx {
  baseUrl: string;
  token: string;
  configured: boolean;
  setConfig: (url: string, token: string) => void;
  data: Overview | null;
  status: ConnStatus;
  error: string | null;
  lastUpdated: Date | null;
  busy: boolean;
  refresh: () => Promise<void>;
  actionBusy: string | null;
  runAction: <T>(label: string, fn: (a: NexusApi) => Promise<T>) => Promise<T>;
  api: () => NexusApi; // cliente REST configurado, para leituras extras (logs/health)
}

const Ctx = createContext<NexusCtx | null>(null);

export function useNexus(): NexusCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error("useNexus deve ser usado dentro de <NexusProvider>");
  return c;
}

export function isStale(lastUpdated: Date | null): boolean {
  return !!lastUpdated && Date.now() - lastUpdated.getTime() > STALE_MS;
}

export function NexusProvider({ children }: { children: ReactNode }) {
  const [baseUrl, setBaseUrl] = useState(localStorage.getItem("nexus_url") || "http://127.0.0.1:8000");
  const [token, setToken] = useState(sessionStorage.getItem("nexus_token") || "");
  const [data, setData] = useState<Overview | null>(null);
  const [status, setStatus] = useState<ConnStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionBusy, setActionBusy] = useState<string | null>(null);

  // Remove uma credencial persistida por versões antigas sem reutilizá-la.
  useEffect(() => {
    localStorage.removeItem("nexus_token");
  }, []);

  const configured = baseUrl.trim() !== "" && token.trim() !== "";

  const setConfig = useCallback((url: string, tk: string) => {
    localStorage.setItem("nexus_url", url);
    sessionStorage.setItem("nexus_token", tk);
    localStorage.removeItem("nexus_token");
    setBaseUrl(url);
    setToken(tk);
  }, []);

  const refresh = useCallback(async () => {
    if (!(baseUrl.trim() && token.trim())) {
      setStatus("idle");
      return;
    }
    setBusy(true);
    if (!data) setStatus("loading");
    try {
      const d = (await new NexusApi(baseUrl, token).overview()) as Overview;
      setData(d);
      setStatus("ok");
      setError(null);
      setLastUpdated(new Date());
    } catch (e: any) {
      const msg = e?.message || String(e);
      if (msg.includes("401") || /token/i.test(msg)) setStatus("unauthorized");
      else setStatus("offline");
      setError(msg);
    } finally {
      setBusy(false);
    }
  }, [baseUrl, token, data]);

  // Polling: re-busca ao configurar e a cada POLL_MS.
  useEffect(() => {
    if (!configured) {
      setStatus("idle");
      return;
    }
    refresh();
    const id = setInterval(refresh, POLL_MS);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [configured, baseUrl, token]);

  const runAction = useCallback(
    async <T,>(label: string, fn: (a: NexusApi) => Promise<T>): Promise<T> => {
      setActionBusy(label);
      try {
        const r = await fn(new NexusApi(baseUrl, token));
        await refresh();
        return r;
      } finally {
        setActionBusy(null);
      }
    },
    [baseUrl, token, refresh]
  );

  const api = useCallback(() => new NexusApi(baseUrl, token), [baseUrl, token]);

  const value: NexusCtx = {
    baseUrl, token, configured, setConfig, data, status, error,
    lastUpdated, busy, refresh, actionBusy, runAction, api,
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
