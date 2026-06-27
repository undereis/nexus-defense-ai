"""DPI (Deep Packet Inspection) via Suricata.

O monitor de DDoS (tools/network_monitor.py) só vê VOLUME (quantas
conexões por IP) — nunca o CONTEÚDO do tráfego. Suricata inspeciona o
payload de cada pacote contra um conjunto de assinaturas (regras) e
grava cada alerta como uma linha JSON em eve.json — isso é o que dá à
Nexus visão de "o que é esse tráfego", não só "quanto tráfego tem".

Esta integração não reimplementa Suricata, só:
1. inicia/para o processo Suricata numa interface (subprocess real);
2. lê e interpreta o eve.json que ele já produz (parsing JSON-lines).

NUNCA VALIDADO CONTRA TRÁFEGO REAL — Suricata não está instalado neste
ambiente, e não há captura de pacotes acontecendo. A lógica de
start/stop e o parser de eve.json estão prontos e testados (start/stop
via mock de subprocess; parser via arquivo eve.json real de exemplo,
sem mock), mas o comportamento de ponta a ponta com Suricata de
verdade analisando tráfego real nunca foi confirmado. Antes de operar
isso numa rede de produção, valide manualmente numa interface de teste.
"""

import json
import shutil
import subprocess
import threading

from config import DPI_INTERFACE, DPI_LOG_DIR
from database.db import log_event

_process: subprocess.Popen | None = None
_lock = threading.Lock()


def is_running() -> bool:
    with _lock:
        return _process is not None and _process.poll() is None


def start(interface: str = "") -> str:
    """Inicia o Suricata em modo IDS (só detecta, nunca bloqueia sozinho —
    qualquer ação a partir de um alerta passa pelas tools normais de
    isolamento) numa interface de rede. Grava alertas em
    workdir/dpi/eve.json."""
    global _process
    interface = interface or DPI_INTERFACE
    if not interface:
        return "Nenhuma interface informada. Defina DPI_INTERFACE no .env ou informe o parâmetro 'interface'."
    if not shutil.which("suricata"):
        return (
            "Suricata não está instalado. Instale com: brew install suricata "
            "(macOS) ou apt install suricata (Linux). Sem isso, não há DPI real."
        )
    with _lock:
        if _process is not None and _process.poll() is None:
            return f"Suricata já está rodando (PID {_process.pid})."
        DPI_LOG_DIR.mkdir(parents=True, exist_ok=True)
        try:
            _process = subprocess.Popen(
                ["suricata", "-i", interface, "-l", str(DPI_LOG_DIR)],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
        except OSError as exc:
            return f"Falha ao iniciar o Suricata: {exc}"
    log_event("dpi_started", None, f"interface={interface} pid={_process.pid}", action_taken="iniciado")
    return f"Suricata iniciado na interface {interface} (PID {_process.pid}). Alertas em workdir/dpi/eve.json."


def stop() -> str:
    """Para o processo Suricata, se estiver rodando."""
    global _process
    with _lock:
        if _process is None or _process.poll() is not None:
            return "Suricata não está rodando."
        pid = _process.pid
        _process.terminate()
        try:
            _process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _process.kill()
        _process = None
    log_event("dpi_stopped", None, f"pid={pid}", action_taken="parado")
    return f"Suricata (PID {pid}) parado."


def _read_eve_json_lines() -> list[dict]:
    eve_path = DPI_LOG_DIR / "eve.json"
    if not eve_path.exists():
        return []
    entries = []
    with eve_path.open("r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def list_alerts(limit: int = 20) -> str:
    """Lista os alertas mais recentes detectados pelo Suricata (assinatura,
    categoria, severidade, IPs envolvidos) — o que de fato estava DENTRO
    do tráfego, não só o volume."""
    entries = [e for e in _read_eve_json_lines() if e.get("event_type") == "alert"]
    if not entries:
        return "Nenhum alerta de DPI registrado ainda (ou Suricata nunca rodou)."
    entries = entries[-limit:]
    lines = [f"Últimos {len(entries)} alerta(s) de DPI:"]
    for e in reversed(entries):
        alert = e.get("alert", {})
        lines.append(
            f"  [{e.get('timestamp', '?')}] {alert.get('signature', '?')} "
            f"(severidade {alert.get('severity', '?')}, categoria {alert.get('category', '?')}) "
            f"{e.get('src_ip', '?')}:{e.get('src_port', '?')} -> {e.get('dest_ip', '?')}:{e.get('dest_port', '?')}"
        )
    return "\n".join(lines)


def describe_alert_summary() -> str:
    """Agrega todos os alertas já registrados por assinatura, para ter
    uma visão geral do que mais aparece, em vez de ler alerta por alerta."""
    entries = [e for e in _read_eve_json_lines() if e.get("event_type") == "alert"]
    if not entries:
        return "Nenhum alerta de DPI registrado ainda (ou Suricata nunca rodou)."
    counts: dict[str, int] = {}
    for e in entries:
        sig = e.get("alert", {}).get("signature", "desconhecida")
        counts[sig] = counts.get(sig, 0) + 1
    lines = [f"Resumo de {len(entries)} alerta(s) de DPI, por assinatura:"]
    for sig, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        lines.append(f"  {sig}: {n}")
    return "\n".join(lines)
