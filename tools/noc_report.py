"""Painel/relatório consolidado de operação (NOC) — Fase 8, Frente C.

Junta num só lugar o estado operacional que hoje fica espalhado em várias
tabelas: assinantes (ativos/bloqueados/inadimplentes), saúde dos equipamentos
monitorados (online/offline), chamados de queda abertos e as últimas ações de
bloqueio/desbloqueio. Serve a três saídas:

  - noc_status_report(): texto, para o chat/notify e para compor o resumo
    executivo diário (tools/report.py).
  - noc_status_data(): dict estruturado, base das outras duas.
  - noc_status_pdf(): relatório executivo em PDF com mini-gráficos de barra
    (reportlab). Degrada com elegância se a lib não estiver instalada.

Read-only: só lê e formata, não dispara nenhuma ação.
"""

from datetime import datetime

from config import WORKDIR
from database.db import (
    list_device_outages,
    list_monitored_devices,
    list_subscriber_actions,
    list_subscribers,
)


def noc_status_data() -> dict:
    """Coleta o estado operacional cru num dict (base do texto e do PDF)."""
    subs = list_subscribers()
    total_subs = len(subs)
    blocked = sum(1 for s in subs if s[5] == "bloqueado_inadimplencia")
    active = total_subs - blocked
    pendentes = sum(1 for s in subs if s[6] == "pendente")

    devices = list_monitored_devices()
    dev_online = sum(1 for d in devices if d[7] == "online")
    dev_offline = sum(1 for d in devices if d[7] == "offline")
    dev_unknown = sum(1 for d in devices if d[7] == "unknown")

    open_outages = list_device_outages("aberto", limit=100)
    recent_actions = list_subscriber_actions(None, limit=10)

    return {
        "subscribers": {
            "total": total_subs, "active": active,
            "blocked": blocked, "pending_invoice": pendentes,
        },
        "devices": {
            "total": len(devices), "online": dev_online,
            "offline": dev_offline, "unknown": dev_unknown,
        },
        "open_outages": open_outages,
        "recent_actions": recent_actions,
    }


def noc_status_report() -> str:
    """Resumo operacional em texto (chat/notify)."""
    d = noc_status_data()
    s, dev = d["subscribers"], d["devices"]
    lines = ["═══ PAINEL NOC ═══", ""]
    lines.append(
        f"Assinantes: {s['total']} (ativos {s['active']}, "
        f"bloqueados {s['blocked']}, fatura pendente {s['pending_invoice']})"
    )
    lines.append(
        f"Equipamentos: {dev['total']} (online {dev['online']}, "
        f"offline {dev['offline']}, desconhecido {dev['unknown']})"
    )

    lines.append("")
    if d["open_outages"]:
        lines.append(f"Chamados de queda ABERTOS ({len(d['open_outages'])}):")
        for device_id, ip, name, reason, _st, opened_at, _res in d["open_outages"][:10]:
            lines.append(f"  🔴 {name or device_id} ({ip}) — {reason} — desde {opened_at}")
    else:
        lines.append("Nenhum chamado de queda aberto. ✅")

    lines.append("")
    if d["recent_actions"]:
        lines.append("Últimas ações de assinante:")
        for sid, action, reason, created_at in d["recent_actions"]:
            lines.append(f"  {created_at} [{sid}] {action} — {reason}")
    else:
        lines.append("Nenhuma ação de assinante registrada ainda.")

    return "\n".join(lines)


# ---------- PDF (opcional, reportlab) ----------

def _draw_bar_group(c, x, y, width, title, items):
    """Desenha um mini-gráfico de barras horizontais com reportlab canvas.
    items: lista de (rótulo, valor, (r,g,b)). Sem matplotlib."""
    from reportlab.lib import colors

    c.setFont("Helvetica-Bold", 11)
    c.drawString(x, y, title)
    y -= 18
    max_val = max((v for _, v, _ in items), default=0) or 1
    bar_h, gap, label_w, bar_max = 14, 8, 130, width - 130 - 40
    for label, value, rgb in items:
        c.setFont("Helvetica", 9)
        c.drawString(x, y - bar_h + 3, f"{label}")
        c.setFillColor(colors.Color(*rgb))
        bar_len = (value / max_val) * bar_max
        c.rect(x + label_w, y - bar_h, bar_len, bar_h, fill=1, stroke=0)
        c.setFillColor(colors.black)
        c.drawString(x + label_w + bar_len + 4, y - bar_h + 3, str(value))
        y -= bar_h + gap
    return y - 10


def noc_status_pdf(path: str = "") -> str:
    """Gera um relatório executivo NOC em PDF (reportlab) com mini-gráficos.
    Retorna o caminho gerado, ou uma mensagem clara se reportlab não estiver
    instalado. O arquivo fica sob WORKDIR (nunca fora dele)."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError:
        return ("Geração de PDF indisponível: reportlab não está instalado. "
                "Rode `venv/bin/pip install reportlab`. O relatório em texto "
                "(noc_status_report) continua funcionando.")

    data = noc_status_data()
    s, dev = data["subscribers"], data["devices"]

    if path:
        out = path
    else:
        WORKDIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = str(WORKDIR / f"noc_report_{stamp}.pdf")

    c = canvas.Canvas(out, pagesize=A4)
    width, height = A4
    margin = 50
    y = height - margin

    c.setFont("Helvetica-Bold", 18)
    c.drawString(margin, y, "Relatório NOC — Nexus Defense AI")
    y -= 22
    c.setFont("Helvetica", 10)
    c.drawString(margin, y, f"Gerado em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 30

    # azul (ok), vermelho (bloqueado/offline), cinza (desconhecido)
    blue, red, gray, amber = (0.16, 0.5, 0.73), (0.78, 0.22, 0.22), (0.6, 0.6, 0.6), (0.9, 0.6, 0.1)
    y = _draw_bar_group(c, margin, y, width - 2 * margin, "Assinantes", [
        ("Ativos", s["active"], blue),
        ("Bloqueados", s["blocked"], red),
        ("Fatura pendente", s["pending_invoice"], amber),
    ])
    y = _draw_bar_group(c, margin, y, width - 2 * margin, "Equipamentos", [
        ("Online", dev["online"], blue),
        ("Offline", dev["offline"], red),
        ("Desconhecido", dev["unknown"], gray),
    ])

    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin, y, f"Chamados de queda abertos: {len(data['open_outages'])}")
    y -= 16
    c.setFont("Helvetica", 9)
    for device_id, ip, name, reason, _st, opened_at, _res in data["open_outages"][:12]:
        c.drawString(margin + 10, y, f"🔴 {name or device_id} ({ip}) — {reason} — {opened_at}"[:110])
        y -= 12
        if y < margin:
            c.showPage()
            y = height - margin

    c.showPage()
    c.save()
    return f"Relatório NOC gerado: {out}"
