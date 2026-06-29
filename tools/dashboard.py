"""Dashboard web read-only (Frente H).

Uma visão de relance, no navegador, do estado de operação (NOC) e segurança:
assinantes, equipamentos/quedas, IPs bloqueados, eventos recentes da auditoria,
honeypots e ações pendentes. Só LEITURA — não dispara nada.

Servido por api/server.py: a página (/dashboard) é uma casca HTML estática que
busca os dados em /dashboard/data, este sim protegido pelo token da API.
"""

from collections import Counter
from datetime import datetime, timezone

from database.db import (
    get_events_since,
    list_blocked_ips,
    list_device_outages,
    list_monitored_devices,
    list_pending_actions,
    list_subscribers,
)


def dashboard_data() -> dict:
    """Agrega o estado atual num dict JSON-serializável (consumido pelo front)."""
    subs = list_subscribers()
    devs = list_monitored_devices()
    events = get_events_since(24)
    event_counts = Counter(e[0] for e in events)
    blocked = list_blocked_ips()

    try:
        from tools import honeypot
        honeypots = [f"{s}:{p}" for s, p in honeypot.list_running()]
    except Exception:
        honeypots = []

    recent = [
        {"time": e[4], "type": e[0], "ip": e[1] or "", "detail": (e[2] or "")[:140],
         "action": e[3] or ""}
        for e in events[-20:]
    ][::-1]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "subscribers": {
            "total": len(subs),
            "blocked": sum(1 for s in subs if s[5] == "bloqueado_inadimplencia"),
            "pending_invoice": sum(1 for s in subs if s[6] == "pendente"),
        },
        "devices": {
            "total": len(devs),
            "online": sum(1 for d in devs if d[7] == "online"),
            "offline": sum(1 for d in devs if d[7] == "offline"),
            "offline_list": [{"id": d[0], "name": d[1], "ip": d[2]} for d in devs if d[7] == "offline"],
        },
        "open_outages": [
            {"id": o[0], "ip": o[1], "name": o[2], "reason": o[3], "since": o[5]}
            for o in list_device_outages("aberto", limit=50)
        ],
        "blocked_ips": [
            {"ip": b[0], "since": b[1], "reason": b[2] or ""} for b in blocked[:50]
        ],
        "blocked_count": len(blocked),
        "events_24h": sum(event_counts.values()),
        "event_top": event_counts.most_common(8),
        "recent_events": recent,
        "honeypots": honeypots,
        "pending_actions": len(list_pending_actions()),
    }


# Página estática: pede o token (sessionStorage), busca /dashboard/data e
# renderiza. Sem CDN/externos. Auto-refresh a cada 15s.
_HTML = """<!doctype html>
<html lang="pt-br"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nexus — Dashboard</title>
<style>
  :root { --bg:#0f1419; --card:#1a212b; --fg:#e6edf3; --muted:#8b98a5;
          --ok:#2ecc71; --warn:#e0a416; --bad:#e05a4f; --accent:#2a89c4; }
  * { box-sizing:border-box; } body { margin:0; background:var(--bg); color:var(--fg);
      font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; }
  header { padding:16px 20px; border-bottom:1px solid #283039; display:flex;
           justify-content:space-between; align-items:center; }
  h1 { font-size:18px; margin:0; } .muted { color:var(--muted); font-size:12px; }
  main { padding:20px; max-width:1100px; margin:0 auto; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; }
  .card { background:var(--card); border:1px solid #283039; border-radius:10px; padding:14px; }
  .card .n { font-size:26px; font-weight:700; } .card .l { color:var(--muted); font-size:12px; }
  .bad .n { color:var(--bad); } .warn .n { color:var(--warn); } .ok .n { color:var(--ok); }
  section { margin-top:24px; } h2 { font-size:14px; color:var(--muted);
           text-transform:uppercase; letter-spacing:.05em; }
  table { width:100%; border-collapse:collapse; } td,th { text-align:left; padding:6px 8px;
          border-bottom:1px solid #232b34; font-size:13px; } th { color:var(--muted); }
  code { background:#222b35; padding:1px 5px; border-radius:4px; }
  .empty { color:var(--muted); padding:8px; } .err { color:var(--bad); }
</style></head>
<body>
<header><h1>Nexus Defense AI — Dashboard</h1>
  <span class="muted" id="ts">carregando…</span></header>
<main id="root"><p class="muted">Carregando…</p></main>
<script>
const $ = (h)=>{const t=document.createElement('template');t.innerHTML=h.trim();return t.content.firstChild;};
function tok(){ let t=sessionStorage.getItem('nexus_token');
  if(!t){ t=prompt('Token da API da Nexus (Bearer):')||''; sessionStorage.setItem('nexus_token',t);} return t; }
function card(n,l,cls){ return `<div class="card ${cls||''}"><div class="n">${n}</div><div class="l">${l}</div></div>`; }
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
async function load(){
  let r;
  try { r = await fetch('/dashboard/data',{headers:{Authorization:'Bearer '+tok()}}); }
  catch(e){ document.getElementById('root').innerHTML='<p class="err">Sem conexão com a API.</p>'; return; }
  if(r.status===401){ sessionStorage.removeItem('nexus_token');
    document.getElementById('root').innerHTML='<p class="err">Token inválido. Recarregue para tentar de novo.</p>'; return; }
  const d = await r.json();
  document.getElementById('ts').textContent = 'atualizado '+d.generated_at;
  const s=d.subscribers, dev=d.devices;
  let h = '<div class="cards">'
    + card(s.total,'Assinantes')
    + card(s.blocked,'Bloqueados', s.blocked? 'bad':'')
    + card(dev.online,'Equip. online','ok')
    + card(dev.offline,'Equip. offline', dev.offline? 'bad':'')
    + card(d.open_outages.length,'Quedas abertas', d.open_outages.length? 'bad':'')
    + card(d.blocked_count,'IPs bloqueados', d.blocked_count? 'warn':'')
    + card(d.events_24h,'Eventos 24h')
    + card(d.pending_actions,'Ações pendentes', d.pending_actions? 'warn':'')
    + '</div>';

  h += sec('Quedas de equipamento (abertas)', d.open_outages,
        ['name','ip','reason','since'], r=>[esc(r.name||r.id), `<code>${esc(r.ip)}</code>`, esc(r.reason), esc(r.since)]);
  h += sec('IPs bloqueados', d.blocked_ips,
        ['ip','since','reason'], r=>[`<code>${esc(r.ip)}</code>`, esc(r.since), esc(r.reason)]);
  h += sec('Honeypots ativos', d.honeypots.map(x=>({x})), ['serviço'], r=>[`<code>${esc(r.x)}</code>`]);
  h += sec('Eventos recentes', d.recent_events,
        ['time','type','ip','detail'], r=>[esc(r.time), esc(r.type), `<code>${esc(r.ip)}</code>`, esc(r.detail)]);
  document.getElementById('root').innerHTML = h;
}
function sec(title, rows, cols, mapfn){
  let h = `<section><h2>${title}</h2>`;
  if(!rows || !rows.length){ return h + '<p class="empty">— nada —</p></section>'; }
  h += '<table><tr>'+cols.map(c=>`<th>${c}</th>`).join('')+'</tr>';
  for(const r of rows){ h += '<tr>'+mapfn(r).map(c=>`<td>${c}</td>`).join('')+'</tr>'; }
  return h + '</table></section>';
}
load(); setInterval(load, 15000);
</script></body></html>"""


def dashboard_html() -> str:
    return _HTML
