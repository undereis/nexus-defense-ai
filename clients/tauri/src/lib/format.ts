// Helpers puros de apresentação — severidade, tempo relativo, classificação de
// IP (detecção de inconsistência) e nível de risco. Tudo derivado dos DADOS
// REAIS da API; nada é inventado.

export type Severity = "bad" | "warn" | "info" | "ok";

// Shape do /api/overview (== dashboard_data do backend). Read-only.
export interface Overview {
  generated_at: string;
  subscribers: { total: number; blocked: number; pending_invoice: number };
  devices: {
    total: number; online: number; offline: number;
    offline_list: { id: string; name: string; ip: string }[];
  };
  open_outages: { device_id: string; ip: string; name: string; reason: string; since: string }[];
  blocked_ips: { ip: string; since: string; reason: string }[];
  blocked_count: number;
  events_24h: number;
  event_top: [string, number][];
  recent_events: { type: string; ip: string; detail: string; action: string; time: string }[];
  honeypots: string[];
  pending_actions: number;
}

const SEV_BAD = ["severe", "failed", "falhou", "error", "erro", "down", "drift", "locked", "capped", "unauthorized", "refus"];
const SEV_WARN = ["suspect", "hit", "warn", "match", "captur", "changed", "mudan", "ratelimit", "throttle", "escalad", "poison"];
const SEV_OK = ["confirmed", "confirmad", "_up", "online", "executed", "executad", "healed", "recuper", "desbloque", "normaliz", "unblock"];

export function severityOf(eventType: string): Severity {
  const t = (eventType || "").toLowerCase();
  if (SEV_BAD.some((k) => t.includes(k))) return "bad";
  if (SEV_WARN.some((k) => t.includes(k))) return "warn";
  if (SEV_OK.some((k) => t.includes(k))) return "ok";
  return "info";
}

export function parseTs(s: string): Date | null {
  if (!s) return null;
  if (s.includes("T")) {
    const d = new Date(s);
    return isNaN(+d) ? null : d;
  }
  // "YYYY-MM-DD HH:MM:SS" — o SQLite grava em UTC sem marcador de fuso.
  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/);
  if (!m) {
    const d = new Date(s);
    return isNaN(+d) ? null : d;
  }
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
}

export function relativeTime(s: string): string {
  const d = parseTs(s);
  if (!d) return s || "—";
  const sec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (sec < 0) return "agora";
  if (sec < 60) return `há ${sec}s`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `há ${min} min`;
  const h = Math.floor(min / 60);
  if (h < 24) return `há ${h}h`;
  return `há ${Math.floor(h / 24)}d`;
}

export interface IpFlag { suspicious: boolean; reason: string; }

// Detecta IPs que NÃO deveriam estar numa blocklist pública (loopback,
// privados, reservados) — sinal de inconsistência operacional.
export function classifyIp(ip: string): IpFlag {
  const m = (ip || "").match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return { suspicious: false, reason: "" };
  const o = m.slice(1, 5).map(Number);
  if (o.some((x) => x > 255)) return { suspicious: true, reason: "octeto inválido" };
  if (o[0] === 127) return { suspicious: true, reason: "loopback (127.0.0.0/8) — não deveria estar bloqueado" };
  if (o[0] === 10) return { suspicious: true, reason: "IP privado (10.0.0.0/8) na blocklist" };
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return { suspicious: true, reason: "IP privado (172.16/12) na blocklist" };
  if (o[0] === 192 && o[1] === 168) return { suspicious: true, reason: "IP privado (192.168/16) na blocklist" };
  if (o[0] === 169 && o[1] === 254) return { suspicious: true, reason: "link-local (169.254/16) na blocklist" };
  if (o[0] === 198 && (o[1] === 18 || o[1] === 19)) return { suspicious: true, reason: "rede de benchmark (198.18/15) na blocklist" };
  if (o[0] === 0 || o[0] >= 224) return { suspicious: true, reason: "endereço reservado/multicast na blocklist" };
  return { suspicious: false, reason: "" };
}

export interface Risk { level: Severity; label: string; reasons: string[]; }

export function riskLevel(d: Overview): Risk {
  const reasons: string[] = [];
  let bad = false, warn = false;
  const susp = d.blocked_ips.filter((b) => classifyIp(b.ip).suspicious);
  if (susp.length) { bad = true; reasons.push(`${susp.length} IP(s) inconsistente(s) na blocklist`); }
  if (d.devices.offline > 0) { bad = true; reasons.push(`${d.devices.offline} equipamento(s) offline`); }
  if (d.open_outages.length > 0) { bad = true; reasons.push(`${d.open_outages.length} queda(s) aberta(s)`); }
  if (d.pending_actions > 0) { warn = true; reasons.push(`${d.pending_actions} ação(ões) de alto risco pendente(s)`); }
  if (d.subscribers.blocked > 0) { warn = true; reasons.push(`${d.subscribers.blocked} assinante(s) bloqueado(s)`); }
  if (bad) return { level: "bad", label: "Crítico", reasons };
  if (warn) return { level: "warn", label: "Atenção", reasons };
  return { level: "ok", label: "Estável", reasons: reasons.length ? reasons : ["Sem incidentes ativos"] };
}
