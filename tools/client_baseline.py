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
    get_client_traffic_slot_coverage,
    list_client_profiles as _db_list_client_profiles,
    record_client_traffic_sample,
    remove_client_profile as _db_remove_client_profile,
)
from tools.robust_stats import median_mad, modified_z_score

MIN_SAMPLES = 5
DEFAULT_Z_THRESHOLD = 3.0
_TOTAL_WEEKLY_SLOTS = 24 * 7  # 168 combinações hora×dia-da-semana


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


def _baseline_stats(client_id: str, hour: int, dow: int):
    """(mean, stdev, median, mad, n) do slot do cliente, ou None se insuficiente."""
    rows = get_client_traffic_samples_for_slot(client_id, hour, dow)
    if len(rows) < MIN_SAMPLES:
        return None
    totals = [r[0] for r in rows]
    mean = statistics.mean(totals)
    stdev = statistics.stdev(totals) if len(totals) > 1 else 0.0
    median, mad = median_mad(totals)
    return mean, stdev, median, mad, len(rows)


def check_client_anomaly(client_id: str, total_connections: int,
                          now: datetime | None = None,
                          z_threshold: float = DEFAULT_Z_THRESHOLD) -> dict:
    """Compara o volume atual de um cliente com a sua baseline. Roda o z-score
    clássico (média/desvio) e o ROBUSTO (mediana/MAD, anti-envenenamento) em
    paralelo: is_anomaly dispara se qualquer um cruzar o threshold; o robusto
    só acrescenta detecção. `poisoning_suspected` marca quando só o robusto
    acusa (média possivelmente arrastada)."""
    now = now or datetime.now(timezone.utc)
    stats = _baseline_stats(client_id, now.hour, now.weekday())
    if stats is None:
        return {
            "is_anomaly": False,
            "reason": "baseline insuficiente",
            "samples_used": 0,
            "client_id": client_id,
        }
    mean, stdev, median, mad, n = stats
    if stdev == 0:
        z_score = float("inf") if total_connections != mean else 0.0
    else:
        z_score = (total_connections - mean) / stdev
    robust_z = modified_z_score(total_connections, median, mad)
    classic_anom = z_score >= z_threshold
    robust_anom = robust_z >= z_threshold
    return {
        "is_anomaly": classic_anom or robust_anom,
        "z_score": round(z_score, 2) if z_score != float("inf") else z_score,
        "robust_z_score": round(robust_z, 2) if robust_z != float("inf") else robust_z,
        "classic_anomaly": classic_anom,
        "robust_anomaly": robust_anom,
        "poisoning_suspected": robust_anom and not classic_anom,
        "mean": round(mean, 1),
        "stdev": round(stdev, 1),
        "median": round(median, 1),
        "mad": round(mad, 1),
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
    text = (
        f"Cliente '{client_id}' ({cidr}): {result['current']} conexões — {status}.\n"
        f"Baseline deste horário: média={result['mean']}, "
        f"desvio={result['stdev']} ({result['samples_used']} amostras). "
        f"Z-score clássico: {result['z_score']} | robusto "
        f"(mediana={result['median']}, MAD={result['mad']}): {result['robust_z_score']}"
    )
    if result.get("poisoning_suspected"):
        text += (
            "\nATENÇÃO: só o detector robusto acusa anomalia — possível "
            "envenenamento lento da baseline deste cliente (média arrastada)."
        )
    return text


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
            mean, stdev, median, mad, n = stats
            lines.append(
                f"  {client_id} ({cidr}): média={round(mean,1)} "
                f"desvio={round(stdev,1)} mediana={round(median,1)} "
                f"MAD={round(mad,1)} ({n} amostras)"
            )
    return "\n".join(lines)


def describe_client_baseline_maturity(client_id: str) -> str:
    """Quão pronta está a baseline de UM cliente: cobertura dos 168 slots
    semanais (hora×dia) e quantos já têm amostras suficientes — onde a detecção
    daquele cliente já vale e onde ainda é cega."""
    profile = get_client_profile(client_id)
    if not profile:
        return (
            f"Cliente '{client_id}' não encontrado. "
            "Cadastre com add_client_profile."
        )
    coverage = get_client_traffic_slot_coverage(client_id)
    total = sum(c for _h, _d, c in coverage)
    slots_with_any = len(coverage)
    slots_ready = sum(1 for _h, _d, c in coverage if c >= MIN_SAMPLES)
    pct_ready = 100.0 * slots_ready / _TOTAL_WEEKLY_SLOTS
    if slots_ready == 0:
        status = "ainda CEGA (nenhum slot com histórico suficiente)"
    elif pct_ready < 50:
        status = "PARCIAL (só parte da semana coberta)"
    else:
        status = "BOA cobertura"
    return (
        f"Maturidade da baseline do cliente '{client_id}':\n"
        f"  Amostras: {total} | slots com dado: {slots_with_any}/{_TOTAL_WEEKLY_SLOTS} | "
        f"slots prontos (>= {MIN_SAMPLES}): {slots_ready}/{_TOTAL_WEEKLY_SLOTS} "
        f"({pct_ready:.0f}%)\n  Status: {status}"
    )
