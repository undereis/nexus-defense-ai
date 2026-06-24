import sqlite3
from contextlib import contextmanager
from config import DB_PATH

DB_PATH.parent.mkdir(parents=True, exist_ok=True)

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    event_type TEXT NOT NULL,
    source_ip TEXT,
    detail TEXT,
    action_taken TEXT
);

CREATE TABLE IF NOT EXISTS conversation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    role TEXT NOT NULL,
    content TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY,
    blocked_at TEXT NOT NULL DEFAULT (datetime('now')),
    reason TEXT
);

CREATE TABLE IF NOT EXISTS threat_intel (
    ip TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    times_flagged INTEGER NOT NULL DEFAULT 0,
    times_isolated INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scan_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    summary TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_scan_findings_host ON scan_findings(host);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def log_event(event_type: str, source_ip: str | None, detail: str, action_taken: str = ""):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO events (event_type, source_ip, detail, action_taken) VALUES (?, ?, ?, ?)",
            (event_type, source_ip, detail, action_taken),
        )


def save_message(role: str, content: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO conversation (role, content) VALUES (?, ?)",
            (role, content),
        )


def get_recent_messages(limit: int = 20):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT role, content FROM conversation ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return list(reversed(rows))


def record_blocked_ip(ip: str, reason: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip, reason) VALUES (?, ?)",
            (ip, reason),
        )


def remove_blocked_ip(ip: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))


def list_blocked_ips():
    with get_conn() as conn:
        return conn.execute("SELECT ip, blocked_at, reason FROM blocked_ips").fetchall()


def record_threat_flag(ip: str):
    """Registra que um IP foi sinalizado como suspeito (acima do threshold)."""
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO threat_intel (ip, times_flagged) VALUES (?, 1)
            ON CONFLICT(ip) DO UPDATE SET
                times_flagged = times_flagged + 1,
                last_seen = datetime('now')
            """,
            (ip,),
        )


def record_threat_isolation(ip: str):
    """Registra que um IP foi efetivamente isolado pelo firewall."""
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO threat_intel (ip, times_flagged, times_isolated) VALUES (?, 0, 1)
            ON CONFLICT(ip) DO UPDATE SET
                times_isolated = times_isolated + 1,
                last_seen = datetime('now')
            """,
            (ip,),
        )


def get_threat_history(ip: str):
    """Retorna (first_seen, last_seen, times_flagged, times_isolated) ou None."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT first_seen, last_seen, times_flagged, times_isolated "
            "FROM threat_intel WHERE ip = ?",
            (ip,),
        ).fetchone()


def list_repeat_offenders(min_score: int = 1):
    """Lista IPs com histórico de ataque, ordenados por reincidência."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT ip, times_flagged, times_isolated, last_seen FROM threat_intel "
            "WHERE (times_flagged + times_isolated) >= ? "
            "ORDER BY times_isolated DESC, times_flagged DESC",
            (min_score,),
        ).fetchall()


def record_finding(host: str, scan_type: str, summary: str):
    """Persiste o resultado de um scan de segurança (nmap, nikto, ssl, etc)
    para o host, formando um histórico de postura de segurança ao longo
    do tempo — sem isso, cada scan se perdia quando a conversa rotacionava."""
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO scan_findings (host, scan_type, summary) VALUES (?, ?, ?)",
            (host, scan_type, summary),
        )


def get_findings_for_host(host: str, limit: int = 10):
    """Retorna os achados mais recentes de um host, do mais novo ao mais antigo."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT scan_type, summary, created_at FROM scan_findings "
            "WHERE host = ? ORDER BY id DESC LIMIT ?",
            (host, limit),
        ).fetchall()


def list_scanned_hosts():
    """Lista todos os hosts já auditados, com a data do scan mais recente."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT host, MAX(created_at) as last_scan, COUNT(*) as total "
            "FROM scan_findings GROUP BY host ORDER BY last_scan DESC"
        ).fetchall()
