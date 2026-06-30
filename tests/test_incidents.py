"""Case management / incidentes (Prioridade 6) — tools/incidents.py."""

import pytest

import database.db as db_module
from tools import incidents


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "test.db")
    db_module.init_db()
    yield


def test_open_and_report():
    msg = incidents.open_incident("DDoS em 203.0.113.5", "high", owner="soc", related_ip="203.0.113.5")
    assert "INC-0001" in msg
    rep = incidents.incident_report("INC-0001")
    assert "DDoS" in rep and "high" in rep and "soc" in rep
    assert "incidente aberto" in rep  # timeline inicial


def test_parse_id_variants():
    incidents.open_incident("teste", "low")
    for ref in (1, "1", "INC-0001", "inc-1"):
        assert "teste" in incidents.incident_report(ref)


def test_status_lifecycle_and_resolved_at():
    incidents.open_incident("caso", "medium")
    assert "investigating" in incidents.set_incident_status(1, "investigating")
    assert "encerrado" in incidents.set_incident_status(1, "resolved")
    row = db_module.get_incident(1)
    assert row[3] == "resolved" and row[13]  # status + resolved_at preenchido


def test_invalid_status_and_severity():
    assert "inválid" in incidents.open_incident("x", "ultra").lower()
    incidents.open_incident("y", "low")
    assert "inválid" in incidents.set_incident_status(1, "bogus").lower()


def test_notes_evidence_actions():
    incidents.open_incident("z", "low")
    incidents.add_note(1, "primeira nota")
    incidents.add_evidence(1, "pcap anexado")
    incidents.record_action(1, "IP isolado")
    rep = incidents.incident_report(1)
    assert "primeira nota" in rep and "pcap anexado" in rep and "IP isolado" in rep


def test_evidence_is_redacted():
    incidents.open_incident("cred", "high")
    incidents.add_evidence(1, "credencial capturada password=hunter2secret")
    rep = incidents.incident_report(1)
    assert "hunter2secret" not in rep
    # e a trilha de auditoria também não vaza
    blob = " ".join(str(e) for e in db_module.get_all_events())
    assert "hunter2secret" not in blob


def test_list_and_filter():
    incidents.open_incident("aberto-1", "low")
    incidents.open_incident("aberto-2", "low")
    incidents.set_incident_status(2, "resolved")
    assert "INC-0001" in incidents.list_incidents_report("open")
    assert "INC-0002" not in incidents.list_incidents_report("open")
    assert "INC-0002" in incidents.list_incidents_report("resolved")


def test_not_found():
    assert "não encontrado" in incidents.incident_report("INC-9999")
    assert "não encontrado" in incidents.add_note(999, "x")


def test_link_event():
    incidents.open_incident("evt", "low")
    assert "vinculado" in incidents.link_event(1, 42)
    assert "42" in incidents.incident_report(1)
