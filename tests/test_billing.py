"""Testes do bloqueio de inadimplentes (Fase 8 — tools/billing.py).

Cobre: fonte local de cobrança (inadimplentes/reativáveis), bloqueio/
desbloqueio com auditoria, idempotência por status, o CAP de segurança que
aborta um lote anormal, a recusa de bloquear IP de infraestrutura, o dry-run
e a fonte externa não-wirada.

O MikroTik é mockado (object-form monkeypatch em billing.mikrotik...), então
nada toca um roteador real. A notificação é capturada.
"""

import pytest

import database.db as db_module
from tools import billing, infrastructure


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    db_module.init_db()
    yield


@pytest.fixture
def fake_mikrotik(monkeypatch):
    calls = {"block": [], "unblock": []}

    def fake_block(ip):
        calls["block"].append(ip)
        return f"IP {ip} bloqueado (forward/drop)."

    def fake_unblock(ip):
        calls["unblock"].append(ip)
        return f"IP {ip} desbloqueado (1 regra(s) removida(s))."

    monkeypatch.setattr(billing.mikrotik, "block_subscriber_ip", fake_block)
    monkeypatch.setattr(billing.mikrotik, "unblock_subscriber_ip", fake_unblock)
    return calls


@pytest.fixture
def captured_notify(monkeypatch):
    sent = []
    monkeypatch.setattr(
        billing.notify, "send_notification",
        lambda title, message: sent.append((title, message)) or True,
    )
    return sent


def _event_types():
    with db_module.get_conn() as conn:
        return [r[0] for r in conn.execute("SELECT event_type FROM events").fetchall()]


# ---------- fonte local ----------

def test_local_source_lists_delinquent_and_reactivatable():
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="pendente", days_overdue=7)
    db_module.add_subscriber("c2", "203.0.113.6", invoice_status="em_dia")
    db_module.add_subscriber("c3", "203.0.113.7", invoice_status="pendente", days_overdue=2)

    source = billing.get_billing_source()
    delinquent = source.list_delinquent(5)
    ids = {d["subscriber_id"] for d in delinquent}
    assert ids == {"c1"}  # c2 em dia, c3 só 2 dias

    # c1 bloqueado e depois regulariza → vira reativável
    db_module.set_subscriber_status("c1", "bloqueado_inadimplencia")
    db_module.set_subscriber_invoice_status("c1", "em_dia", 0)
    react = source.list_reactivated()
    assert [r["subscriber_id"] for r in react] == ["c1"]


# ---------- bloqueio / auditoria ----------

def test_cycle_blocks_delinquent_and_audits(fake_mikrotik, captured_notify):
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="pendente", days_overdue=10)

    summary = billing.run_billing_cycle(min_days=5)

    assert fake_mikrotik["block"] == ["203.0.113.5"]
    row = db_module.get_subscriber("c1")
    assert row[5] == "bloqueado_inadimplencia"  # status
    actions = [a[1] for a in db_module.list_subscriber_actions("c1")]
    assert "bloqueado" in actions
    assert "billing_cycle_done" in _event_types()
    assert captured_notify  # resumo notificado
    assert "Bloqueados: 1" in summary


def test_already_blocked_not_reblocked(fake_mikrotik):
    # já bloqueado → não aparece em list_delinquent (filtra status='ativo')
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="pendente", days_overdue=10)
    db_module.set_subscriber_status("c1", "bloqueado_inadimplencia")

    billing.run_billing_cycle(min_days=5)
    assert fake_mikrotik["block"] == []

    # e o bloqueio ad-hoc também é idempotente pelo status
    msg = billing.block_subscriber_by_id("c1")
    assert "já está bloqueado" in msg
    assert fake_mikrotik["block"] == []


def test_reactivation_unblocks(fake_mikrotik):
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="em_dia")
    db_module.set_subscriber_status("c1", "bloqueado_inadimplencia")

    billing.run_billing_cycle(min_days=5)
    assert fake_mikrotik["unblock"] == ["203.0.113.5"]
    assert db_module.get_subscriber("c1")[5] == "ativo"
    actions = [a[1] for a in db_module.list_subscriber_actions("c1")]
    assert "desbloqueado" in actions


# ---------- CAP de segurança ----------

def test_cap_aborts_whole_cycle(fake_mikrotik, captured_notify):
    for i in range(6):
        db_module.add_subscriber(f"c{i}", f"203.0.113.{10 + i}",
                                 invoice_status="pendente", days_overdue=9)

    summary = billing.run_billing_cycle(min_days=5, max_batch=3)

    assert "ABORTADO POR SEGURANÇA" in summary
    assert fake_mikrotik["block"] == []  # ninguém bloqueado
    # nenhum status mudou
    assert all(db_module.get_subscriber(f"c{i}")[5] == "ativo" for i in range(6))
    assert "billing_cycle_capped" in _event_types()
    assert captured_notify and "ABORTADO" in captured_notify[0][1]


# ---------- proteção de infraestrutura ----------

def test_refuses_to_block_infra_ip(fake_mikrotik):
    infrastructure.register_ip_block("203.0.113.0/24", "Bloco crítico", is_critical=True)
    db_module.add_subscriber("infra1", "203.0.113.5", invoice_status="pendente", days_overdue=9)

    billing.run_billing_cycle(min_days=5)

    assert fake_mikrotik["block"] == []  # nunca bloqueou
    assert db_module.get_subscriber("infra1")[5] == "ativo"  # status intacto
    actions = [a[1] for a in db_module.list_subscriber_actions("infra1")]
    assert "bloqueio_recusado" in actions
    assert "subscriber_block_refused" in _event_types()


# ---------- dry-run ----------

def test_dry_run_changes_nothing(fake_mikrotik):
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="pendente", days_overdue=10)

    summary = billing.run_billing_cycle(min_days=5, dry_run=True)

    assert "DRY-RUN" in summary
    assert fake_mikrotik["block"] == []
    assert db_module.get_subscriber("c1")[5] == "ativo"


# ---------- fonte externa não wirada ----------

def test_external_source_not_configured(monkeypatch, fake_mikrotik):
    monkeypatch.setattr(billing, "BILLING_SOURCE", "external")
    db_module.add_subscriber("c1", "203.0.113.5", invoice_status="pendente", days_overdue=10)

    summary = billing.run_billing_cycle(min_days=5)
    assert "abortado" in summary.lower()
    assert "externa" in summary.lower()
    assert fake_mikrotik["block"] == []
