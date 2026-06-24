"""Monitoramento de rede e heurística de detecção de DDoS/anomalias."""

import subprocess
import time
from collections import Counter, deque

import psutil

from config import CONNECTIONS_PER_IP_THRESHOLD, MONITOR_WINDOW_SECONDS

_warned_once = False


def _warn_once(message: str):
    global _warned_once
    if not _warned_once:
        _warned_once = True
        print(f"\n[Nexus] {message}")


def _get_active_remote_ips_psutil() -> list[str] | None:
    """Tenta via psutil (mais rico, mas exige root no macOS). Retorna None
    se não tiver permissão, para o caller cair no fallback via netstat."""
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return None
    return [c.raddr.ip for c in conns if c.status == psutil.CONN_ESTABLISHED and c.raddr]


def _get_active_remote_ips_netstat() -> list[str]:
    """Lê conexões TCP estabelecidas via `netstat -an`, que no macOS não
    exige privilégios de root (diferente de psutil.net_connections)."""
    try:
        result = subprocess.run(
            ["netstat", "-an", "-p", "tcp"], capture_output=True, text=True, timeout=10
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        _warn_once(f"AVISO: netstat indisponível para monitorar a rede ({exc}).")
        return []

    ips = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[-1] != "ESTABLISHED":
            continue
        foreign = fields[-2]
        if "." not in foreign:
            continue
        addr = foreign.rsplit(".", 1)[0]
        if addr and addr != "*":
            ips.append(addr)
    return ips


def get_active_remote_ips() -> list[str]:
    """Retorna a lista de IPs remotos com conexão estabelecida agora.
    Usa psutil quando possível (roda com sudo); senão cai para netstat,
    que funciona sem privilégios elevados no macOS."""
    ips = _get_active_remote_ips_psutil()
    if ips is not None:
        return ips
    return _get_active_remote_ips_netstat()


class DdosDetector:
    """Mantém uma janela deslizante de amostras de IPs conectados e
    sinaliza um IP como suspeito quando aparece com frequência muito
    acima do normal dentro da janela de tempo configurada."""

    def __init__(self, window_seconds: int = MONITOR_WINDOW_SECONDS, threshold: int = CONNECTIONS_PER_IP_THRESHOLD):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self._samples: deque[tuple[float, str]] = deque()

    def sample(self) -> list[str]:
        """Coleta uma amostra atual e retorna lista de IPs que ultrapassaram o threshold."""
        now = time.time()
        for ip in get_active_remote_ips():
            self._samples.append((now, ip))

        cutoff = now - self.window_seconds
        while self._samples and self._samples[0][0] < cutoff:
            self._samples.popleft()

        counts = Counter(ip for _, ip in self._samples)
        return [ip for ip, count in counts.items() if count >= self.threshold]

    def snapshot_counts(self) -> Counter:
        return Counter(ip for _, ip in self._samples)
