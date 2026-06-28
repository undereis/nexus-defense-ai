"""Baseline de tráfego por cliente (Xfiber).

Complementa tools/anomaly.py (detecção global) com baseline individual por
cliente. Cada cliente da Xfiber tem um CIDR registrado e o sistema aprende
o padrão de tráfego DAQUELE cliente por horário/dia da semana.

Resultado: um cliente fazendo 3× o seu volume normal às 3h da manhã é
detectado mesmo que o volume total da rede esteja dentro do padrão —
algo impossível com a detecção global.

Mesma abordagem estatística de tools/anomaly.py (z-score) mas isolada
por client_id × hora × dia_da_semana.

Fluxo:
  1. add_client_profile("xfiber-empresa-xyz", "200.100.50.0/24", "Empresa XYZ")
  2. O monitor_loop chama record_all_client_samples(counts) a cada ciclo
  3. Após dias/semanas de histórico, check_all_client_anomalies(counts)
     começa a detectar desvios específicos de cada cliente.
"""

import ipaddress
import statistics
from datetime import datetime, timezone

from database.db import (
    add_client_profile as _db_add_client_profile,
    get_client_profile,
    get_client_traffic_samples_for_slot,
    list_client_profiles as _db_list_client_profiles,
    record_client_traffic_sample,
    remove_client_profile as _db_remove_client_profile,
)

MIN_SAMPLES = 5
DEFAULT_Z_THRESHOLD = 3.0


def _ip_to_client(ip: str) -> str | None:
    """Encontra o client_id cujo CIDR contém este IP. None se não mapeado."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for client_id, cidr, *_ in _db_list_client_profiles():
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return client_id
        except ValueError:
            continue
    return None


def add_client_profile(client_id: str, cidr: str, description: str = "") -> str:
    """Cadastra um cliente da Xfiber com o seu bloco IP."""
    try:
        cidr = str(ipaddress.ip_network(cidr, strict=False))
    except ValueError as exc:
        return f"CIDR inválido: {exc}"
    _db_add_client_profile(client_id, cidr, description)
    return f"Cliente '{client_id}' cadastrado com CIDR {cidr}."


def remove_client_profile(client_id: str) -> str:
    """Remove um cliente do registro (não apaga amostras históricas)."""
    _db_remove_client_profile(client_id)
    return f"Cliente '{client_id}' removido."


def list_client_profiles() -> str:
    """Lista todos os clientes cadastrados com seus CIDRs."""
    rows = _db_list_client_profiles()
    if not rows:
        return "Nenhum cliente cadastrado. Use add_client_profile para começar."
    lines = [f"Clientes cadastrados ({len(rows)}):"]
    for client_id, cidr, description, added_at in rows:
        lines.append(
            f"  {client_id} | {cidr}"
            f" — {description or 'sem descrição'} (desde {added_at[:10]})"
        )
    return "\n".join(lines)


def record_all_client_samples(counts: dict[str, int],
                                now: datetime | None = None) -> None:
    """Agrega contagens de conexões por IP em amostras por cliente.
    Chamado pelo monitor_loop a cada ciclo."""
    now = now or datetime.now(timezone.utc)
    client_totals: dict[str, int] = {}
    client_ips: dict[str, set] = {}
    for ip, conn_count in counts.items():
        cid = _ip_to_client(ip)
        if cid is None:
            continue
        client_totals[cid] = client_totals.get(cid, 0) + conn_count
        client_ips.setdefault(cid, set()).add(ip)
    for cid, total in client_totals.items():
        record_client_traffic_sample(
            cid, now.hour, now.weekday(), total, len(client_ips[cid])
        )


def _baseline_stats(client_id: str, hour: int,
                     dow: int) -> tuple[float, float, int] | None:
    rows = get_client_traffic_samples_for_slot(client_id, hour, dow)
    if len(rows) < MIN_SAMPLES:
        return None
    totals = [r[0] for r in rows]
    mean = statistics.mean(totals)
    stdev = statistics.stdev(totals) if len(totals) > 1 else 0.0
    return mean, stdev, len(rows)


def check_client_anomaly(client_id: str, total_connections: int,
                          now: datetime | None = None,
                          z_threshold: float = DEFAULT_Z_THRESHOLD) -> dict:
    """Compara o volume atual de um cliente com a sua baseline.
    Retorna dict com is_anomaly, z_score, mean, stdev, samples_used."""
    now = now or datetime.now(timezone.utc)
    stats = _baseline_stats(client_id, now.hour, now.weekday())
    if stats is None:
        return {
            "is_anomaly": False,
            "reason": "baseline insuficiente",
            "samples_used": 0,
            "client_id": client_id,
        }
    mean, stdev, n = stats
    if stdev == 0:
        z_score = float("inf") if total_connections != mean else 0.0
    else:
        z_score = (total_connections - mean) / stdev
    return {
        "is_anomaly": z_score >= z_threshold,
        "z_score": round(z_score, 2) if z_score != float("inf") else z_score,
        "mean": round(mean, 1),
        "stdev": round(stdev, 1),
        "samples_used": n,
        "current": total_connections,
        "client_id": client_id,
    }


def check_all_client_anomalies(counts: dict[str, int],
                                 now: datetime | None = None,
                                 z_threshold_fn=None) -> list[dict]:
    """Verifica anomalias para TODOS os clientes com base nas contagens atuais.
    Retorna lista de resultados onde is_anomaly=True.

    z_threshold_fn opcional: callable(client_id) -> float. Quando fornecido, o
    threshold de cada cliente é resolvido por ela — é o gancho pelo qual o
    modelo de risco por cliente (tools/client_risk) deixa a detecção mais
    agressiva para clientes arriscados. Sem ela, usa o DEFAULT_Z_THRESHOLD
    (comportamento original preservado)."""
    now = now or datetime.now(timezone.utc)
    client_totals: dict[str, int] = {}
    for ip, conn_count in counts.items():
        cid = _ip_to_client(ip)
        if cid:
            client_totals[cid] = client_totals.get(cid, 0) + conn_count
    anomalies = []
    for cid, total in client_totals.items():
        z = z_threshold_fn(cid) if z_threshold_fn else DEFAULT_Z_THRESHOLD
        result = check_client_anomaly(cid, total, now, z_threshold=z)
        if result.get("is_anomaly"):
            anomalies.append(result)
    return anomalies


def describe_client_anomaly_status(client_id: str,
                                    total_connections: int,
                                    now: datetime | None = None) -> str:
    """Versão em texto de check_client_anomaly para a tool do agente."""
    profile = get_client_profile(client_id)
    if not profile:
        return (
            f"Cliente '{client_id}' não encontrado. "
            "Cadastre com add_client_profile."
        )
    _, cidr, description, _ = profile
    result = check_client_anomaly(client_id, total_connections, now)
    if result["samples_used"] == 0:
        return (
            f"Cliente '{client_id}' ({cidr} — {description or 'sem descrição'}): "
            "ainda não há baseline suficiente para este horário. "
            "A detecção fica útil após algumas semanas de histórico cobrindo "
            "os mesmos horários várias vezes."
        )
    status = "ANOMALIA DETECTADA" if result["is_anomaly"] else "dentro do padrão normal"
    return (
        f"Cliente '{client_id}' ({cidr}): {result['current']} conexões — {status}.\n"
        f"Baseline deste horário: média={result['mean']}, "
        f"desvio={result['stdev']} ({result['samples_used']} amostras). "
        f"Z-score: {result['z_score']}"
    )


def describe_all_client_baselines() -> str:
    """Resume o status de baseline de todos os clientes cadastrados."""
    rows = _db_list_client_profiles()
    if not rows:
        return "Nenhum cliente cadastrado."
    lines = ["Status de baseline por cliente:"]
    for client_id, cidr, description, _ in rows:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        stats = _baseline_stats(client_id, now.hour, now.weekday())
        if stats is None:
            lines.append(
                f"  {client_id} ({cidr}): baseline insuficiente "
                f"(menos de {MIN_SAMPLES} amostras neste horário)"
            )
        else:
            mean, stdev, n = stats
            lines.append(
                f"  {client_id} ({cidr}): média={round(mean,1)} "
                f"desvio={round(stdev,1)} ({n} amostras)"
            )
    return "\n".join(lines)
