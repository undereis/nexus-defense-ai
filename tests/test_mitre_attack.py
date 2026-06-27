"""Testes para tools/mitre_attack.py — mapeamento para MITRE ATT&CK."""

from tools import mitre_attack


def test_map_known_event_type():
    ttp = mitre_attack.map_event_to_ttp("ddos_severe")
    assert ttp["technique_id"] == "T1498"
    assert ttp["tactic"] == "Impact"
    assert "attack.mitre.org" in ttp["mitre_url"]


def test_map_unknown_event_type_is_honest():
    ttp = mitre_attack.map_event_to_ttp("evento_que_nao_existe")
    assert ttp["technique_id"] == "—"
    assert ttp["tactic"] == "Unknown"


def test_map_honeypot_service():
    ttp = mitre_attack.map_honeypot_service_to_ttp("ftp")
    assert ttp["technique_id"] == "T1110"


def test_describe_ttp_known():
    text = mitre_attack.describe_ttp("hydra_attempt")
    assert "T1110" in text
    assert "Brute Force" in text


def test_describe_ttp_unknown():
    text = mitre_attack.describe_ttp("nao_existe")
    assert "ainda não tem TTP" in text


def test_summarize_ttps_for_ip_combines_events_and_honeypot_services():
    result = mitre_attack.summarize_ttps_for_ip(["ddos_severe", "sqlmap_attempt"], ["ftp"])
    assert "T1498" in result
    assert "T1190" in result
    assert "T1110" in result


def test_summarize_ttps_for_ip_deduplicates_same_technique():
    result = mitre_attack.summarize_ttps_for_ip(["hydra_attempt"], ["ftp"])
    # hydra_attempt e ftp honeypot mapeiam pra mesma técnica T1110 — não deve duplicar
    assert result.count("T1110") == 1


def test_summarize_ttps_for_ip_empty_returns_honest_message():
    result = mitre_attack.summarize_ttps_for_ip([], [])
    assert "Nenhuma TTP" in result
