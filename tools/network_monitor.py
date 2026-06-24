"""Monitoramento de rede e heurística de detecção de DDoS/anomalias."""

import time
from collections import Counter, deque

import psutil

from config import CONNECTIONS_PER_IP_THRESHOLD, MONITOR_WINDOW_SECONDS


def get_active_remote_ips() -> list[str]:
    """Retorna a lista de IPs remotos com conexão estabelecida agora."""
    ips = []
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return ips
    for c in conns:
        if c.status == psutil.CONN_ESTABLISHED and c.raddr:
            ips.append(c.raddr.ip)
    return ips


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
