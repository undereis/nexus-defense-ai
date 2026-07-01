// Wrapper REST do Nexus para o cliente Tauri.
//
// Usa o `fetch` do PLUGIN HTTP do Tauri (@tauri-apps/plugin-http), que executa
// a requisição no Rust (nativo) em vez do webview — assim NÃO há restrição de
// CORS e o servidor/API permanecem intactos. Autenticação por Bearer token,
// igual ao contrato em docs/api.md.

import { fetch } from "@tauri-apps/plugin-http";

export class NexusApi {
  constructor(public baseUrl: string, public token: string) {}

  private async req(method: "GET" | "POST", path: string, body?: unknown): Promise<any> {
    const url = this.baseUrl.replace(/\/+$/, "") + path;
    const headers: Record<string, string> = { Authorization: `Bearer ${this.token}` };
    const init: Record<string, unknown> = { method, headers };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    const res = await fetch(url, init);
    if (res.status === 401) {
      throw new Error("Token inválido ou ausente (HTTP 401).");
    }
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`HTTP ${res.status}: ${text.slice(0, 300)}`);
    }
    return res.json();
  }

  // --- consultas ---
  overview() { return this.req("GET", "/api/overview"); }
  health() { return this.req("GET", "/api/health"); }
  subscribers() { return this.req("GET", "/api/subscribers"); }
  devices() { return this.req("GET", "/api/devices"); }
  outages(status = "aberto") {
    return this.req("GET", `/api/outages?status=${encodeURIComponent(status)}`);
  }
  events(hours = 24) {
    return this.req("GET", `/api/events?hours=${hours}`);
  }

  // --- ações ---
  block(id: string, reason: string) {
    return this.req("POST", `/api/subscribers/${encodeURIComponent(id)}/block?reason=${encodeURIComponent(reason)}`);
  }
  unblock(id: string, reason: string) {
    return this.req("POST", `/api/subscribers/${encodeURIComponent(id)}/unblock?reason=${encodeURIComponent(reason)}`);
  }
  runBilling(dryRun: boolean) {
    return this.req("POST", `/api/billing/run?dry_run=${dryRun ? "true" : "false"}`);
  }
  checkDevices() {
    return this.req("POST", "/api/devices/check");
  }

  // --- modo operacional do motor (backend) ---
  getMode() { return this.req("GET", "/api/mode"); }
  setMode(mode: string) { return this.req("POST", "/api/mode", { mode }); }
}
