import hashlib
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from config import DB_PATH

DB_PATH.parent.mkdir(parents=True, exist_ok=True)

GENESIS_HASH = "0" * 64
_event_chain_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    event_type TEXT NOT NULL,
    source_ip TEXT,
    detail TEXT,
    action_taken TEXT,
    prev_hash TEXT,
    entry_hash TEXT
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

CREATE TABLE IF NOT EXISTS authorized_assets (
    host TEXT PRIMARY KEY,
    added_at TEXT NOT NULL DEFAULT (datetime('now')),
    interval_hours REAL NOT NULL DEFAULT 24,
    last_scan_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    event_count INTEGER NOT NULL,
    last_event_id INTEGER NOT NULL,
    last_entry_hash TEXT NOT NULL,
    sent_externally INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS honeypot_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    service TEXT NOT NULL DEFAULT 'ssh',
    timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_honeypot_hits_ip ON honeypot_hits(ip);

CREATE TABLE IF NOT EXISTS honeypot_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    service TEXT NOT NULL,
    username TEXT,
    password TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_honeypot_credentials_ip ON honeypot_credentials(ip);

CREATE TABLE IF NOT EXISTS knowledge_documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    topic TEXT NOT NULL,
    title TEXT NOT NULL,
    source_url TEXT NOT NULL,
    content TEXT NOT NULL,
    fetched_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
    title, content, topic, content='knowledge_documents', content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS knowledge_documents_ai AFTER INSERT ON knowledge_documents BEGIN
    INSERT INTO knowledge_fts(rowid, title, content, topic) VALUES (new.id, new.title, new.content, new.topic);
END;

CREATE TRIGGER IF NOT EXISTS knowledge_documents_ad AFTER DELETE ON knowledge_documents BEGIN
    INSERT INTO knowledge_fts(knowledge_fts, rowid, title, content, topic) VALUES ('delete', old.id, old.title, old.content, old.topic);
END;

CREATE TABLE IF NOT EXISTS pending_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL,
    args_json TEXT NOT NULL,
    summary TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at TEXT,
    expires_at TEXT NOT NULL
);
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
        # Migração para bancos criados antes da trilha de auditoria com hash
        # chain existir: adiciona as colunas sem perder eventos já gravados.
        for column in ("prev_hash TEXT", "entry_hash TEXT"):
            try:
                conn.execute(f"ALTER TABLE events ADD COLUMN {column}")
            except sqlite3.OperationalError:
                pass  # coluna já existe
        try:
            conn.execute("ALTER TABLE honeypot_hits ADD COLUMN service TEXT NOT NULL DEFAULT 'ssh'")
        except sqlite3.OperationalError:
            pass  # coluna já existe


def _compute_entry_hash(prev_hash: str, timestamp: str, event_type: str,
                         source_ip: str | None, detail: str, action_taken: str) -> str:
    payload = "|".join([prev_hash, timestamp, event_type, source_ip or "", detail, action_taken])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_event(event_type: str, source_ip: str | None, detail: str, action_taken: str = ""):
    """Grava um evento de auditoria encadeado por hash: cada entrada inclui
    o hash da entrada anterior, formando uma cadeia (como um mini-blockchain
    local). Qualquer alteração retroativa de um evento já gravado quebra a
    cadeia a partir desse ponto — verificável com tools/audit.verify_chain()."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with _event_chain_lock:
        with get_conn() as conn:
            row = conn.execute(
                "SELECT entry_hash FROM events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = (row[0] if row and row[0] else GENESIS_HASH)
            entry_hash = _compute_entry_hash(
                prev_hash, timestamp, event_type, source_ip, detail, action_taken
            )
            conn.execute(
                "INSERT INTO events (timestamp, event_type, source_ip, detail, "
                "action_taken, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (timestamp, event_type, source_ip, detail, action_taken, prev_hash, entry_hash),
            )


def get_all_events():
    """Retorna todos os eventos em ordem, com os campos do hash chain, para
    verificação de integridade."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT id, timestamp, event_type, source_ip, detail, action_taken, "
            "prev_hash, entry_hash FROM events ORDER BY id ASC"
        ).fetchall()


def get_events_since(hours: float):
    """Retorna (event_type, source_ip, detail, action_taken, timestamp) dos
    eventos das últimas N horas — base para o resumo executivo periódico."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT event_type, source_ip, detail, action_taken, timestamp FROM events "
            "WHERE timestamp >= datetime('now', ?) ORDER BY id ASC",
            (f"-{hours} hours",),
        ).fetchall()


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


def add_authorized_asset(host: str, interval_hours: float = 24):
    """Autoriza um host a ser reauditado automaticamente pela Nexus em
    intervalos regulares. Nunca é feito sem essa autorização explícita."""
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO authorized_assets (host, interval_hours) VALUES (?, ?)
            ON CONFLICT(host) DO UPDATE SET interval_hours = excluded.interval_hours
            """,
            (host, interval_hours),
        )


def remove_authorized_asset(host: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM authorized_assets WHERE host = ?", (host,))


def list_authorized_assets():
    """Retorna (host, added_at, interval_hours, last_scan_at) de todos os ativos."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT host, added_at, interval_hours, last_scan_at FROM authorized_assets"
        ).fetchall()


def touch_asset_scan(host: str):
    """Marca que um ativo autorizado acabou de ser reauditado agora."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE authorized_assets SET last_scan_at = datetime('now') WHERE host = ?",
            (host,),
        )


def get_latest_finding(host: str, scan_type: str):
    """Retorna (summary,) do achado mais recente de um tipo específico, ou None."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT summary FROM scan_findings WHERE host = ? AND scan_type = ? "
            "ORDER BY id DESC LIMIT 1",
            (host, scan_type),
        ).fetchone()


def save_audit_checkpoint(event_count: int, last_event_id: int, last_entry_hash: str, sent_externally: bool):
    """Registra um checkpoint do estado da trilha de auditoria: quantos
    eventos existiam e qual era o hash do último, num dado momento. Usado
    para detectar truncamento (remoção de eventos do FINAL da cadeia, que
    o hash chain por si só não detecta)."""
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO audit_checkpoints (event_count, last_event_id, last_entry_hash, sent_externally) "
            "VALUES (?, ?, ?, ?)",
            (event_count, last_event_id, last_entry_hash, 1 if sent_externally else 0),
        )


def get_latest_audit_checkpoint():
    """Retorna (created_at, event_count, last_event_id, last_entry_hash, sent_externally) ou None."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT created_at, event_count, last_event_id, last_entry_hash, sent_externally "
            "FROM audit_checkpoints ORDER BY id DESC LIMIT 1"
        ).fetchone()


def record_honeypot_hit(ip: str, port: int, service: str = "ssh"):
    """Registra que um IP conectou na porta-armadilha — diferente da
    detecção por volume de tráfego, isto é praticamente prova direta de
    varredura/ataque, já que nenhum cliente legítimo deveria conectar
    nessa porta."""
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO honeypot_hits (ip, port, service) VALUES (?, ?, ?)",
            (ip, port, service),
        )


def list_honeypot_hits(limit: int = 20):
    """Retorna (ip, port, service, timestamp) das conexões mais recentes na armadilha."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT ip, port, service, timestamp FROM honeypot_hits ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()


def count_honeypot_hits(ip: str) -> int:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM honeypot_hits WHERE ip = ?", (ip,)
        ).fetchone()
        return row[0] if row else 0


def record_honeypot_credential(ip: str, port: int, service: str, username: str | None, password: str | None):
    """Registra usuário/senha que um atacante digitou de verdade no
    honeypot — inteligência muito mais rica que só saber que ele
    conectou: agora sabemos o que ele tentou usar."""
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO honeypot_credentials (ip, port, service, username, password) "
            "VALUES (?, ?, ?, ?, ?)",
            (ip, port, service, username, password),
        )


def list_honeypot_credentials(limit: int = 50):
    """Retorna (ip, port, service, username, password, timestamp) capturados."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT ip, port, service, username, password, timestamp "
            "FROM honeypot_credentials ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()


def list_honeypot_hits_for_ip(ip: str, limit: int = 20):
    """Retorna (port, service, timestamp) das conexões de um IP específico."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT port, service, timestamp FROM honeypot_hits WHERE ip = ? "
            "ORDER BY id DESC LIMIT ?",
            (ip, limit),
        ).fetchall()


def list_honeypot_credentials_for_ip(ip: str, limit: int = 20):
    """Retorna (port, service, username, password, timestamp) capturados de um IP específico."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT port, service, username, password, timestamp FROM honeypot_credentials "
            "WHERE ip = ? ORDER BY id DESC LIMIT ?",
            (ip, limit),
        ).fetchall()


def add_knowledge_document(topic: str, title: str, source_url: str, content: str) -> int:
    """Adiciona um documento técnico à base de conhecimento local (full-text
    indexado via FTS5). Retorna o id do documento inserido."""
    with get_conn() as conn:
        cursor = conn.execute(
            "INSERT INTO knowledge_documents (topic, title, source_url, content) VALUES (?, ?, ?, ?)",
            (topic, title, source_url, content),
        )
        return cursor.lastrowid


def search_knowledge(query: str, limit: int = 5):
    """Busca full-text na base de conhecimento. Retorna (id, topic, title,
    source_url, snippet) ordenado por relevância. Termos da query são
    combinados com OR, cada um como frase exata sanitizada (evita erro de
    sintaxe do FTS5 com caracteres especiais como -, *, etc)."""
    terms = [t.replace('"', '""') for t in query.split() if t.strip()]
    if not terms:
        return []
    match_expr = " OR ".join(f'"{t}"' for t in terms)

    with get_conn() as conn:
        return conn.execute(
            """
            SELECT kd.id, kd.topic, kd.title, kd.source_url,
                   snippet(knowledge_fts, 1, '>>', '<<', '...', 40) as snippet
            FROM knowledge_fts
            JOIN knowledge_documents kd ON kd.id = knowledge_fts.rowid
            WHERE knowledge_fts MATCH ?
            ORDER BY rank
            LIMIT ?
            """,
            (match_expr, limit),
        ).fetchall()


def list_knowledge_topics():
    """Retorna (topic, total_docs) agrupado por tópico."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT topic, COUNT(*) FROM knowledge_documents GROUP BY topic ORDER BY topic"
        ).fetchall()


def get_knowledge_document(doc_id: int):
    """Retorna (topic, title, source_url, content, fetched_at) de um documento pelo id."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT topic, title, source_url, content, fetched_at FROM knowledge_documents WHERE id = ?",
            (doc_id,),
        ).fetchone()


def create_pending_action(tool_name: str, args_json: str, summary: str, ttl_minutes: int = 10) -> int:
    """Registra uma ação de alto risco aguardando confirmação explícita do
    criador. Retorna o id da ação pendente."""
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO pending_actions (tool_name, args_json, summary, expires_at)
            VALUES (?, ?, ?, datetime('now', ?))
            """,
            (tool_name, args_json, summary, f"+{ttl_minutes} minutes"),
        )
        return cur.lastrowid


def get_pending_action(action_id: int):
    """Retorna (id, tool_name, args_json, summary, status, created_at, resolved_at, expires_at)."""
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT id, tool_name, args_json, summary, status, created_at, resolved_at, expires_at
            FROM pending_actions WHERE id = ?
            """,
            (action_id,),
        ).fetchone()


def resolve_pending_action(action_id: int, status: str):
    """Marca uma ação pendente como 'executada', 'cancelada' ou 'expirada'."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE pending_actions SET status = ?, resolved_at = datetime('now') WHERE id = ?",
            (status, action_id),
        )


def list_pending_actions():
    """Lista ações com status 'pending' que ainda não expiraram."""
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT id, tool_name, summary, created_at, expires_at
            FROM pending_actions
            WHERE status = 'pending' AND expires_at > datetime('now')
            ORDER BY created_at
            """
        ).fetchall()
