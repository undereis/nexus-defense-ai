"""Testes para tools/tool_fingerprint.py — análise de ferramentas do
atacante (Fase 6, item 2).

Classificadores puros (User-Agent, credenciais, comportamento) testados
diretamente. A agregação por IP semeia o DB temp com sinais reais
(honeytoken_triggers via plant+trigger, honeypot_credentials, honeypot_hits)
e mocka só o seam de DPI (dpi.get_alert_entries), object-form.
"""

import database.db as db
import pytest

from tools import dpi, tool_fingerprint as tf


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    yield


# ---------- classify_user_agent (puro) ----------

def test_ua_sqlmap():
    c = tf.classify_user_agent("sqlmap/1.7.2#stable (http://sqlmap.org)")
    assert c["tool"] == "sqlmap"
    assert c["confidence"] == "alta"


def test_ua_nmap_masscan_zgrab():
    assert tf.classify_user_agent("Mozilla/5.0 Nmap Scripting Engine")["tool"] == "Nmap (NSE)"
    assert tf.classify_user_agent("masscan/1.3")["tool"] == "masscan"
    assert tf.classify_user_agent("Mozilla/5.0 zgrab/0.x")["tool"] == "ZMap/zgrab"


def test_ua_scripted_clients():
    assert tf.classify_user_agent("python-requests/2.31.0")["tool"] == "script Python"
    assert tf.classify_user_agent("Go-http-client/1.1")["tool"] == "Go-http-client"
    assert tf.classify_user_agent("curl/8.1.2")["tool"] == "curl"


def test_ua_empty_is_botlike():
    c = tf.classify_user_agent("")
    assert c["tool"] == "sem User-Agent"
    assert c["confidence"] == "média"


def test_ua_browser_low_confidence():
    c = tf.classify_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120")
    assert c["tool"] == "navegador (ou UA forjado)"
    assert c["confidence"] == "baixa"


def test_ua_unknown():
    c = tf.classify_user_agent("XyzCustomAgent/9")
    assert c["tool"] == "desconhecido"


# ---------- classify_credentials (puro) ----------

def test_creds_mirai():
    c = tf.classify_credentials([("root", "xc3511"), ("root", "vizxv"), ("admin", "admin")])
    assert c["family"] == "botnet IoT estilo Mirai"
    assert c["confidence"] == "alta"


def test_creds_common_defaults():
    # 1 default comum, mas <2 do dicionário Mirai específico
    c = tf.classify_credentials([("oracle", "oracle")])
    assert c["family"] == "brute force com defaults comuns"
    assert c["confidence"] == "média"


def test_creds_custom_wordlist():
    c = tf.classify_credentials([("joao", "S3nh@F0rte!"), ("maria", "Qx92__zz")])
    assert c["family"] == "brute force / wordlist customizada"


def test_creds_none():
    assert tf.classify_credentials([]) is None


def test_creds_handles_none_values():
    # honeypot pode gravar username/password NULL
    c = tf.classify_credentials([(None, None), ("root", "root"), ("admin", "admin")])
    assert c["family"] == "botnet IoT estilo Mirai"  # ("root","root")+("admin","admin") são do set Mirai


# ---------- classify_scan_behavior (puro) ----------

def test_behavior_port_sweep():
    c = tf.classify_scan_behavior(distinct_ports=6, total_hits=6)
    assert "port sweep" in c["type"]


def test_behavior_targeted():
    c = tf.classify_scan_behavior(distinct_ports=1, total_hits=8)
    assert "dirigido" in c["type"]


def test_behavior_light():
    c = tf.classify_scan_behavior(distinct_ports=1, total_hits=1)
    assert "pontual" in c["type"]


def test_behavior_none():
    assert tf.classify_scan_behavior(0, 0) is None


# ---------- agregação por IP (com I/O no DB temp) ----------

def _seed_honeytoken_ua(ip, ua, token_id="tok1"):
    db.plant_honeytoken(token_id, "file", "/srv/secret.txt")
    assert db.record_honeytoken_trigger(token_id, ip, ua)


def test_fingerprint_for_ip_aggregates_all_signals(monkeypatch):
    monkeypatch.setattr(dpi, "get_alert_entries", lambda: [])
    ip = "203.0.113.7"
    _seed_honeytoken_ua(ip, "sqlmap/1.7")
    db.record_honeypot_credential(ip, 22, "ssh", "root", "xc3511")
    db.record_honeypot_credential(ip, 22, "ssh", "root", "vizxv")
    for port in (22, 23, 80, 443, 8080):
        db.record_honeypot_hit(ip, port, "tcp")

    fp = tf.fingerprint_tools_for_ip(ip)
    assert fp["has_signal"]
    assert fp["user_agents"][0]["tool"] == "sqlmap"
    assert fp["credentials"]["family"] == "botnet IoT estilo Mirai"
    assert "port sweep" in fp["behavior"]["type"]


def test_fingerprint_pulls_dpi_user_agents(monkeypatch):
    ip = "203.0.113.8"
    monkeypatch.setattr(dpi, "get_alert_entries", lambda: [
        {"src_ip": ip, "http": {"http_user_agent": "Nikto/2.5"}},
        {"src_ip": "9.9.9.9", "http": {"http_user_agent": "curl/8"}},  # outro IP, ignorar
        {"src_ip": ip, "alert": {"signature": "ET SCAN"}},  # sem http, ignorar
    ])
    fp = tf.fingerprint_tools_for_ip(ip)
    tools = [c["tool"] for c in fp["user_agents"]]
    assert "Nikto" in tools
    assert "curl" not in tools  # do outro IP


def test_fingerprint_dpi_failure_is_silent(monkeypatch):
    ip = "203.0.113.9"
    def boom():
        raise RuntimeError("eve.json corrompido")
    monkeypatch.setattr(dpi, "get_alert_entries", boom)
    db.record_honeypot_hit(ip, 22, "ssh")
    fp = tf.fingerprint_tools_for_ip(ip)  # não deve estourar
    assert fp["has_signal"]
    assert fp["user_agents"] == []


def test_fingerprint_no_signal(monkeypatch):
    monkeypatch.setattr(dpi, "get_alert_entries", lambda: [])
    out = tf.fingerprint_attacker_tools("198.51.100.1")
    assert "Sem sinais" in out


def test_fingerprint_report(monkeypatch):
    monkeypatch.setattr(dpi, "get_alert_entries", lambda: [])
    ip = "203.0.113.10"
    _seed_honeytoken_ua(ip, "Hydra/9.5")
    db.record_honeypot_credential(ip, 21, "ftp", "admin", "admin")
    db.record_honeypot_hit(ip, 21, "ftp")
    out = tf.fingerprint_attacker_tools(ip)
    assert ip in out
    assert "Hydra" in out
    assert "🔑 Credenciais" in out
    assert "📡 Comportamento" in out


def test_describe_user_agent():
    s = tf.describe_user_agent("masscan/1.3")
    assert "masscan" in s
    assert "confiança alta" in s
