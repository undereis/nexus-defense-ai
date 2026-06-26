"""Testes para tools/metrics.py — métricas de evidência derivadas da
trilha de auditoria real (sem mock de persistência).

Como o banco é compartilhado com o resto do projeto (e com execuções
manuais feitas durante o desenvolvimento), os testes evitam assumir
contagens absolutas/exatas — verificam o que aconteceu nesta chamada
específica, não o estado global do banco."""

import time
import uuid

from database.db import get_pending_action, init_db, log_event
from tools import metrics, risk


def setup_function(_):
    init_db()


def test_generate_metrics_report_has_expected_sections():
    report = metrics.generate_metrics_report(hours=1)
    assert "MÉTRICAS DE EVIDÊNCIA" in report
    assert "Governança de ações de alto risco" in report
    assert "Contenção de ameaças" in report
    assert "Estado atual do firewall" in report


def test_governance_breakdown_counts_executed_and_cancelled():
    risk.register_action("metrics_test_a", lambda: "ok")
    msg1 = risk.request_confirmation("metrics_test_a", "ação 1")
    id1 = int(msg1.split("id=")[1].split(")")[0])
    real_code1 = get_pending_action(id1)[4]
    risk.confirm_and_execute(id1, real_code1)

    risk.register_action("metrics_test_b", lambda: "ok")
    msg2 = risk.request_confirmation("metrics_test_b", "ação 2")
    id2 = int(msg2.split("id=")[1].split(")")[0])
    risk.cancel(id2)

    gov = metrics._governance_breakdown(hours=1)
    assert gov["by_status"]["executada"] >= 1
    assert gov["by_status"]["cancelada"] >= 1
    assert gov["total_proposed"] >= 2


def test_containment_breakdown_pairs_detection_with_block_for_specific_ip():
    unique_ip = f"198.51.100.{uuid.uuid4().int % 250 + 1}"
    log_event("ddos_severe", unique_ip, "teste métricas")
    time.sleep(1)
    log_event("firewall_block_attempt", unique_ip, "reason='teste'")
    log_event("firewall_block_confirmed", unique_ip, "reason='teste'")
    log_event("firewall_unblock_confirmed", unique_ip, "")

    cont = metrics._containment_breakdown(hours=1)
    assert cont["ips_blocked"] >= 1
    assert cont["ips_unblocked"] >= 1
    assert cont["avg_detection_to_block_seconds"] is not None
    assert cont["avg_detection_to_block_seconds"] >= 1.0
