"""Testes para tools/ttp_profile.py — perfil de grupo por TTPs (Fase 6, item 3).

Semeio o DB temp com honeypot_hits/events (timestamps explícitos via insert
direto, p/ controlar hora-do-dia e ordem cronológica) e mocko só o seam de
rede `geoip.lookup` (object-form). Janela enorme (BIG) p/ que os timestamps
fixos sempre entrem no filtro de `get_distinct_honeypot_ips_since`.
"""

import database.db as db
import pytest

from tools import geoip, ttp_profile

BIG = 24 * 365 * 50  # janela gigante: timestamps fixos de 2026 sempre dentro


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    yield


def _hit(ip, port, ts, service="ssh"):
    """Insere um honeypot_hit com timestamp explícito (record_honeypot_hit
    usa datetime('now') e não deixa controlar a hora)."""
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO honeypot_hits (ip, port, service, timestamp) VALUES (?, ?, ?, ?)",
            (ip, port, service, ts),
        )


def _fake_geoip(mapping):
    return lambda ip: mapping.get(ip)


def _seed_two_groups(monkeypatch):
    """Grupo A: 2 IPs com mesma sequência de portas/timing/ASN, hora 14.
    Grupo B: 1 IP com portas/ASN/hora diferentes."""
    geo = {
        "1.1.1.1": {"asn": "AS111", "country": "BR"},
        "1.1.1.2": {"asn": "AS111", "country": "BR"},
        "9.9.9.9": {"asn": "AS999", "country": "RU"},
    }
    monkeypatch.setattr(geoip, "lookup", _fake_geoip(geo))
    for ip in ("1.1.1.1", "1.1.1.2"):
        _hit(ip, 22, "2026-06-28 14:00:00")
        _hit(ip, 2222, "2026-06-28 14:00:02")
        _hit(ip, 23, "2026-06-28 14:00:05")
    _hit("9.9.9.9", 3389, "2026-06-28 03:00:00")
    _hit("9.9.9.9", 445, "2026-06-28 03:00:02")
    _hit("9.9.9.9", 3389, "2026-06-28 03:00:05")


# ---------- helpers puros ----------

def test_hour_of():
    assert ttp_profile._hour_of("2026-06-28 14:03:09") == 14
    assert ttp_profile._hour_of("2026-06-28 14:03:09.123456") == 14
    assert ttp_profile._hour_of("lixo") is None


def test_jaccard():
    assert ttp_profile._jaccard({1, 2}, {2, 3}) == 1 / 3
    assert ttp_profile._jaccard(set(), set()) == 0.0
    assert ttp_profile._jaccard({1}, {1}) == 1.0
    assert ttp_profile._jaccard({1}, {2}) == 0.0


# ---------- perfil por IP ----------

def test_build_ip_profile(monkeypatch):
    monkeypatch.setattr(geoip, "lookup", _fake_geoip({"1.1.1.1": {"asn": "AS111", "country": "BR"}}))
    _hit("1.1.1.1", 22, "2026-06-28 14:00:00")
    _hit("1.1.1.1", 2222, "2026-06-28 14:00:02")
    _hit("1.1.1.1", 23, "2026-06-28 14:00:05")
    p = ttp_profile.build_ip_profile("1.1.1.1")
    assert p["asn"] == "AS111"
    assert p["country"] == "BR"
    assert p["ports"] == {22, 2222, 23}
    assert p["hours"] == [14, 14, 14]
    assert p["total_hits"] == 3
    assert "T1595" in p["ttps"]  # honeypot ssh -> Active Scanning


def test_build_ip_profile_private_ip_no_geo(monkeypatch):
    monkeypatch.setattr(geoip, "lookup", lambda ip: None)  # IP privado/sem geo
    _hit("10.0.0.5", 22, "2026-06-28 14:00:00")
    p = ttp_profile.build_ip_profile("10.0.0.5")
    assert p["asn"] == "desconhecido"
    assert p["country"] == "?"


# ---------- clustering ----------

def test_profile_groups_clusters(monkeypatch):
    _seed_two_groups(monkeypatch)
    groups = ttp_profile.profile_groups(BIG)
    assert len(groups) == 2

    g0 = groups[0]  # maior primeiro -> grupo A (2 membros)
    assert g0["size"] == 2
    assert set(g0["members"]) == {"1.1.1.1", "1.1.1.2"}
    assert g0["asns"][0][0] == "AS111"
    assert g0["peak_hours"][0][0] == 14
    assert {22, 2222, 23} <= {p for p, _ in g0["top_ports"]}

    g1 = groups[1]  # grupo B (1 membro), origem/hora distintas
    assert g1["members"] == ["9.9.9.9"]
    assert g1["asns"][0][0] == "AS999"
    assert g1["peak_hours"][0][0] == 3


def test_different_asn_and_ports_do_not_merge(monkeypatch):
    # mesmo TTP (ssh) mas portas e ASN distintos => abaixo do limiar
    _seed_two_groups(monkeypatch)
    groups = ttp_profile.profile_groups(BIG)
    members_b = next(g["members"] for g in groups if "9.9.9.9" in g["members"])
    assert members_b == ["9.9.9.9"]  # não foi absorvido pelo grupo A


def test_skipped_low_hit_ips(monkeypatch):
    geo = {
        "1.1.1.1": {"asn": "AS111", "country": "BR"},
        "1.1.1.2": {"asn": "AS111", "country": "BR"},
        "2.2.2.2": {"asn": "AS222", "country": "BR"},
    }
    monkeypatch.setattr(geoip, "lookup", _fake_geoip(geo))
    for ip in ("1.1.1.1", "1.1.1.2"):
        _hit(ip, 22, "2026-06-28 14:00:00")
        _hit(ip, 2222, "2026-06-28 14:00:02")
        _hit(ip, 23, "2026-06-28 14:00:05")
    _hit("2.2.2.2", 22, "2026-06-28 14:00:00")  # só 1 hit -> abaixo de MIN_HITS

    groups = ttp_profile.profile_groups(BIG)
    assert all("2.2.2.2" not in g["members"] for g in groups)
    out = ttp_profile.profile_attacker_groups(BIG)
    assert "2.2.2.2" in out
    assert "poucos hits" in out


# ---------- inferência de ferramentas a partir de eventos ----------

def test_tool_inference_from_events(monkeypatch):
    monkeypatch.setattr(geoip, "lookup", _fake_geoip({"5.5.5.5": {"asn": "AS5", "country": "BR"}}))
    for i in range(3):
        _hit("5.5.5.5", 80, f"2026-06-28 10:00:0{i}", service="http")
    db.log_event("hydra_attempt", "5.5.5.5", "brute force")
    db.log_event("sqlmap_attempt", "5.5.5.5", "sqli")

    groups = ttp_profile.profile_groups(BIG)
    assert len(groups) == 1
    g = groups[0]
    assert "Hydra (brute force)" in g["tools"]
    assert "SQLMap (SQLi)" in g["tools"]
    assert "T1110" in g["ttps"]  # brute force (hydra / honeypot http)
    assert "T1190" in g["ttps"]  # sqlmap -> exploit public-facing app


# ---------- relatório / which_group ----------

def test_profile_no_data(monkeypatch):
    monkeypatch.setattr(geoip, "lookup", lambda ip: None)
    assert "Nenhum IP" in ttp_profile.profile_attacker_groups(BIG)


def test_profile_attacker_groups_report(monkeypatch):
    _seed_two_groups(monkeypatch)
    out = ttp_profile.profile_attacker_groups(BIG)
    assert "PERFIL DE GRUPOS POR TTP" in out
    assert "2 grupo(s)" in out
    for ip in ("1.1.1.1", "1.1.1.2", "9.9.9.9"):
        assert ip in out
    assert "14h UTC" in out
    assert "Previsão" in out


def test_which_group(monkeypatch):
    _seed_two_groups(monkeypatch)
    out = ttp_profile.which_group("1.1.1.1", BIG)
    assert "pertence ao grupo G1" in out
    assert "1.1.1.2" in out  # outro membro do mesmo grupo

    # IP sem nenhum hit -> não está em grupo nenhum
    assert "não está em nenhum grupo" in ttp_profile.which_group("8.8.8.8", BIG)
