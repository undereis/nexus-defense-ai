// "Nexus IA Insights" — calculados NO FRONTEND a partir dos dados reais da API.
// Não é IA do backend nem dado simulado: é leitura/correlação do que a API já
// devolve, apresentada como recomendação VISUAL (nunca executa ação).

import { Overview, Severity, classifyIp, relativeTime, severityOf } from "./format";
import type { EnvMode } from "./environment";

export interface Insight { severity: Severity; title: string; text: string; }

export function computeInsights(d: Overview): Insight[] {
  const out: Insight[] = [];

  // 1) Inconsistências de IP na blocklist (crítico) — ex.: 127.0.0.1 bloqueado.
  const susp = d.blocked_ips.filter((b) => classifyIp(b.ip).suspicious);
  for (const b of susp.slice(0, 3)) {
    out.push({
      severity: "bad",
      title: `Inconsistência crítica: ${b.ip} bloqueado`,
      text: `${classifyIp(b.ip).reason}. Motivo registrado: ${b.reason || "—"}.`,
    });
  }

  // 2) Equipamentos offline.
  if (d.devices.offline > 0) {
    const names = d.devices.offline_list.map((x) => x.name || x.id).slice(0, 4).join(", ");
    out.push({
      severity: "bad",
      title: `${d.devices.offline} equipamento(s) offline`,
      text: names || "Verifique o NOC.",
    });
  }

  // 3) Quedas abertas.
  if (d.open_outages.length > 0) {
    out.push({
      severity: "bad",
      title: `${d.open_outages.length} queda(s) de equipamento aberta(s)`,
      text: "Há chamados de queda sem resolução.",
    });
  }

  // 4) Ações de alto risco pendentes.
  if (d.pending_actions > 0) {
    out.push({
      severity: "warn",
      title: `${d.pending_actions} ação de alto risco pendente`,
      text: "Aguardando confirmação fora de banda (gate de risco).",
    });
  }

  // 5) Eventos críticos recentes.
  const crit = d.recent_events.filter((e) => severityOf(e.type) === "bad");
  if (crit.length) {
    out.push({
      severity: "warn",
      title: `${crit.length} evento(s) crítico(s) recentes`,
      text: crit.slice(0, 3).map((e) => e.type).join(", "),
    });
  }

  // 6) Último bloqueio (informativo).
  if (d.blocked_ips.length) {
    const last = [...d.blocked_ips].sort((a, b) => (b.since || "").localeCompare(a.since || ""))[0];
    out.push({
      severity: "info",
      title: `Último bloqueio: ${last.ip}`,
      text: `${relativeTime(last.since)} — ${last.reason || "sem motivo registrado"}`,
    });
  }

  // 7) Volume de eventos 24h (informativo).
  out.push({
    severity: "info",
    title: `${d.events_24h} eventos nas últimas 24h`,
    text: d.event_top?.length
      ? `Top: ${d.event_top.slice(0, 3).map(([t, n]) => `${t} (${n})`).join(", ")}`
      : "Sem destaques no período.",
  });

  // 8) Recomendação VISUAL (sem ação automática).
  if (susp.length) {
    out.push({
      severity: "warn",
      title: "Recomendação",
      text: "Revisar a blocklist e remover IPs internos/loopback. A Nexus IA apenas sinaliza — nada é executado automaticamente.",
    });
  } else if (d.devices.offline > 0) {
    out.push({
      severity: "info",
      title: "Recomendação",
      text: "Checar os equipamentos offline. Sinalização apenas; sem ação automática.",
    });
  }

  // 9) Estado bom — só se não houver nada crítico/atenção.
  const anyAttention = out.some((i) => i.severity === "bad" || i.severity === "warn");
  if (!anyAttention) {
    out.unshift({
      severity: "ok",
      title: "Operação estável",
      text: "Sem inconsistências ou incidentes ativos nos dados atuais.",
    });
  }

  return out;
}

// Insights de PRONTIDÃO/PREPARAÇÃO — diferenciam achados reais da ausência de
// laboratório e do modo de visualização. Informativos e visuais; não executam
// nada. Acrescentam-se aos insights operacionais, ao final.
export function readinessInsights(d: Overview, mode: EnvMode): Insight[] {
  const out: Insight[] = [];

  if (d.devices.total === 0) {
    out.push({
      severity: "info",
      title: "Nenhum hardware real conectado ainda",
      text: "Monitoração física aguardando laboratório/equipamentos. A interface está pronta para conectar quando o hardware chegar.",
    });
  }

  out.push({
    severity: "info",
    title: "Mapa operando em modo ilustrativo",
    text: "Sem geolocalização real na API: as posições são esquemáticas. Os IPs plotados, quando houver, são reais.",
  });

  if (mode === "lab") {
    out.push({
      severity: "warn",
      title: "Modo Laboratório ativo",
      text: "Visualizações de demonstração estão marcadas como “Simulação visual”. As métricas seguem reais quando vindas da API.",
    });
  } else if (mode === "replay") {
    out.push({
      severity: "info",
      title: "Nenhum replay disponível na API atual",
      text: "Recurso preparado conceitualmente — será habilitado quando houver endpoint/dados de replay.",
    });
  } else {
    out.push({
      severity: "info",
      title: "Dados de eventos vêm da API real",
      text: "A telemetria exibida é a retornada pelo motor Python; nada é fabricado.",
    });
  }

  return out;
}
