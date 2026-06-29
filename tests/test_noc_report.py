"""Testes do painel/relatório NOC consolidado (Fase 8, Frente C)."""

import pytest

import database.db as db_module
from tools import noc_report


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    db_module.init_db()
    yield


def _seed():
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="pendente", days_overdue=7)
    db_module.add_subscriber("c2", "203.0.113.6")
    db_module.set_subscriber_status("c1", "bloqueado_inadimplencia")
    db_module.record_subscriber_action("c1", "bloqueado", "7 dias de atraso")
    db_module.add_monitored_device("d1", "10.0.0.1", name="OLT-1")
    db_module.add_monitored_device("d2", "10.0.0.2", name="OLT-2")
    db_module.set_device_status("d1", "online")
    db_module.set_device_status("d2", "offline")
    db_module.open_device_outage("d2", "10.0.0.2", "OLT-2", "Sem resposta ao ping")


def test_status_data_counts():
    _seed()
    d = noc_report.noc_status_data()
    assert d["subscribers"] == {"total": 2, "active": 1, "blocked": 1, "pending_invoice": 1}
    assert d["devices"]["online"] == 1
    assert d["devices"]["offline"] == 1
    assert len(d["open_outages"]) == 1
    assert len(d["recent_actions"]) == 1


def test_status_report_text():
    _seed()
    text = noc_report.noc_status_report()
    assert "PAINEL NOC" in text
    assert "Assinantes: 2" in text
    assert "OLT-2" in text  # chamado aberto listado


def test_status_report_empty():
    text = noc_report.noc_status_report()
    assert "Assinantes: 0" in text
    assert "Nenhum chamado de queda aberto" in text


def test_report_integrates_into_executive_summary():
    _seed()
    from tools.report import generate_summary_report
    summary = generate_summary_report(24)
    assert "PAINEL NOC" in summary


def test_pdf_generated_under_workdir(tmp_path):
    _seed()
    out = tmp_path / "noc.pdf"
    msg = noc_report.noc_status_pdf(str(out))
    assert "gerado" in msg.lower()
    assert out.exists()
    # cabeçalho de um PDF válido
    assert out.read_bytes()[:4] == b"%PDF"


def test_pdf_graceful_without_reportlab(monkeypatch):
    """Se reportlab não estiver instalado, degrada com mensagem clara em vez de
    quebrar — o relatório em texto continua funcionando."""
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("reportlab"):
            raise ImportError("simulando ausência de reportlab")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    msg = noc_report.noc_status_pdf()
    assert "reportlab" in msg.lower()
