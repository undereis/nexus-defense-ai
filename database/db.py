import hashlib
import json
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

CREATE TABLE IF NOT EXISTS traffic_baseline_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    hour_of_day INTEGER NOT NULL,
    day_of_week INTEGER NOT NULL,
    total_connections INTEGER NOT NULL,
    distinct_ips INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_traffic_baseline_hour_dow ON traffic_baseline_samples(hour_of_day, day_of_week);

CREATE TABLE IF NOT EXISTS bgp_flowspec_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_text TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'announced',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    withdrawn_at TEXT
);

CREATE TABLE IF NOT EXISTS threat_feed_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    value TEXT NOT NULL,
    fetched_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_threat_feed_entries_source ON threat_feed_entries(source);

CREATE TABLE IF NOT EXISTS honeytokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    location TEXT NOT NULL,
    planted_at TEXT NOT NULL DEFAULT (datetime('now')),
    triggered_count INTEGER NOT NULL DEFAULT 0,
    last_triggered_at TEXT
);

CREATE TABLE IF NOT EXISTS honeytoken_triggers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id TEXT NOT NULL,
    source_ip TEXT,
    user_agent TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_honeytoken_triggers_token ON honeytoken_triggers(token_id);

CREATE TABLE IF NOT EXISTS honeynet_ranges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    declared_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS pending_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL,
    args_json TEXT NOT NULL,
    summary TEXT NOT NULL,
    confirmation_code TEXT NOT NULL DEFAULT '',
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at TEXT,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_limited_ips (
    ip TEXT PRIMARY KEY,
    connections_per_second INTEGER NOT NULL DEFAULT 10,
    rate_limited_at TEXT NOT NULL DEFAULT (datetime('now')),
    reason TEXT
);

CREATE TABLE IF NOT EXISTS playbook_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    level_reached INTEGER NOT NULL,
    actions_json TEXT NOT NULL DEFAULT '[]',
    triggered_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_playbook_executions_ip ON playbook_executions(ip);

CREATE TABLE IF NOT EXISTS asn_blocks (
    asn TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    prefixes_json TEXT NOT NULL DEFAULT '[]',
    prefix_count INTEGER NOT NULL DEFAULT 0,
    blocked_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS infrastructure_ip_blocks (
    cidr TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    is_critical INTEGER NOT NULL DEFAULT 0,
    asn TEXT NOT NULL DEFAULT '',
    added_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS infrastructure_asns (
    asn TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    added_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS infrastructure_nodes (
    name TEXT PRIMARY KEY,
    node_type TEXT NOT NULL DEFAULT 'unknown',
    ip_or_cidr TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    added_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS asset_inventory (
    ip TEXT PRIMARY KEY,
    hostname TEXT NOT NULL DEFAULT '',
    open_ports_json TEXT NOT NULL DEFAULT '[]',
    os_guess TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    status TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS asset_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    change_type TEXT NOT NULL,
    old_value TEXT NOT NULL DEFAULT '',
    new_value TEXT NOT NULL DEFAULT '',
    detected_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_asset_changes_ip ON asset_changes(ip);

CREATE TABLE IF NOT EXISTS client_profiles (
    client_id TEXT PRIMARY KEY,
    cidr TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    added_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS client_traffic_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT NOT NULL,
    hour_of_day INTEGER NOT NULL,
    day_of_week INTEGER NOT NULL,
    total_connections INTEGER NOT NULL,
    distinct_ips INTEGER NOT NULL,
    timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_client_traffic_samples_slot ON client_traffic_samples(client_id, hour_of_day, day_of_week);

CREATE TABLE IF NOT EXISTS dns_servers (
    ip TEXT PRIMARY KEY,
    hostname TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    added_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS dns_health_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    reachable INTEGER NOT NULL DEFAULT 0,
    latency_ms INTEGER NOT NULL DEFAULT -1,
    query_status TEXT NOT NULL DEFAULT '',
    open_ports_json TEXT NOT NULL DEFAULT '[]',
    risky_ports_json TEXT NOT NULL DEFAULT '[]',
    cert_days_left INTEGER,
    problems_json TEXT NOT NULL DEFAULT '[]',
    checked_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_dns_health_checks_ip ON dns_health_checks(ip);
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
        try:
            conn.execute("ALTER TABLE pending_actions ADD COLUMN confirmation_code TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError:
            pass  # coluna já existe
        try:
            conn.execute("ALTER TABLE pending_actions ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0")
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


def create_pending_action(
    tool_name: str, args_json: str, summary: str, confirmation_code: str, ttl_minutes: int = 10
) -> int:
    """Registra uma ação de alto risco aguardando confirmação explícita do
    criador. Retorna o id da ação pendente."""
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO pending_actions (tool_name, args_json, summary, confirmation_code, expires_at)
            VALUES (?, ?, ?, ?, datetime('now', ?))
            """,
            (tool_name, args_json, summary, confirmation_code, f"+{ttl_minutes} minutes"),
        )
        return cur.lastrowid


def get_pending_action(action_id: int):
    """Retorna (id, tool_name, args_json, summary, confirmation_code, status,
    created_at, resolved_at, expires_at, failed_attempts). failed_attempts
    fica no final para não quebrar índices de quem já lê as colunas
    anteriores por posição."""
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT id, tool_name, args_json, summary, confirmation_code, status,
                   created_at, resolved_at, expires_at, failed_attempts
            FROM pending_actions WHERE id = ?
            """,
            (action_id,),
        ).fetchone()


def increment_failed_attempts(action_id: int) -> int:
    """Incrementa o contador de tentativas de código incorreto para uma
    ação pendente e retorna o novo total."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE pending_actions SET failed_attempts = failed_attempts + 1 WHERE id = ?",
            (action_id,),
        )
        row = conn.execute(
            "SELECT failed_attempts FROM pending_actions WHERE id = ?", (action_id,)
        ).fetchone()
        return row[0] if row else 0


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


def get_pending_actions_since(hours: float):
    """Retorna (tool_name, status, created_at, resolved_at) das ações de
    alto risco propostas nas últimas N horas — base para métricas de
    governança (quantas foram aprovadas/canceladas/expiraram, e em
    quanto tempo)."""
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT tool_name, status, created_at, resolved_at
            FROM pending_actions
            WHERE created_at >= datetime('now', ?)
            ORDER BY created_at
            """,
            (f"-{hours} hours",),
        ).fetchall()


def record_traffic_sample(hour_of_day: int, day_of_week: int, total_connections: int, distinct_ips: int):
    """Registra uma amostra de volume de tráfego (total de conexões e IPs
    distintos), marcada por hora do dia (0-23) e dia da semana (0=segunda
    .. 6=domingo) — base para aprender o padrão normal por horário."""
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO traffic_baseline_samples (hour_of_day, day_of_week, total_connections, distinct_ips) "
            "VALUES (?, ?, ?, ?)",
            (hour_of_day, day_of_week, total_connections, distinct_ips),
        )


def get_traffic_samples_for_slot(hour_of_day: int, day_of_week: int, exclude_last_n_minutes: float = 0):
    """Retorna (total_connections, distinct_ips) de todas as amostras
    históricas para o mesmo horário/dia da semana — a base para calcular
    média e desvio padrão do que é 'normal' nesse slot."""
    with get_conn() as conn:
        if exclude_last_n_minutes > 0:
            return conn.execute(
                "SELECT total_connections, distinct_ips FROM traffic_baseline_samples "
                "WHERE hour_of_day = ? AND day_of_week = ? AND timestamp < datetime('now', ?)",
                (hour_of_day, day_of_week, f"-{exclude_last_n_minutes} minutes"),
            ).fetchall()
        return conn.execute(
            "SELECT total_connections, distinct_ips FROM traffic_baseline_samples "
            "WHERE hour_of_day = ? AND day_of_week = ?",
            (hour_of_day, day_of_week),
        ).fetchall()


def count_traffic_samples() -> int:
    with get_conn() as conn:
        row = conn.execute("SELECT COUNT(*) FROM traffic_baseline_samples").fetchone()
        return row[0] if row else 0


def record_flowspec_rule(rule_text: str, description: str) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO bgp_flowspec_rules (rule_text, description) VALUES (?, ?)",
            (rule_text, description),
        )
        return cur.lastrowid


def get_flowspec_rule(rule_id: int):
    """Retorna (id, rule_text, description, status, created_at, withdrawn_at)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT id, rule_text, description, status, created_at, withdrawn_at "
            "FROM bgp_flowspec_rules WHERE id = ?",
            (rule_id,),
        ).fetchone()


def mark_flowspec_rule_withdrawn(rule_id: int):
    with get_conn() as conn:
        conn.execute(
            "UPDATE bgp_flowspec_rules SET status = 'withdrawn', withdrawn_at = datetime('now') WHERE id = ?",
            (rule_id,),
        )


def list_active_flowspec_rules():
    with get_conn() as conn:
        return conn.execute(
            "SELECT id, description, created_at FROM bgp_flowspec_rules "
            "WHERE status = 'announced' ORDER BY created_at"
        ).fetchall()


def get_event_types_for_ip(ip: str) -> list[str]:
    """Retorna os tipos de evento distintos já registrados para um IP
    específico — base para o mapeamento MITRE ATT&CK no dossiê."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT DISTINCT event_type FROM events WHERE source_ip = ?", (ip,)
        ).fetchall()
        return [r[0] for r in rows]


def get_honeypot_services_for_ip(ip: str) -> list[str]:
    """Retorna os serviços de honeypot distintos (ssh/ftp/http) que um IP
    já tocou."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT DISTINCT service FROM honeypot_hits WHERE ip = ?", (ip,)
        ).fetchall()
        return [r[0] for r in rows]


def replace_feed_entries(source: str, entries: list[str]):
    """Substitui todas as entradas de uma fonte de threat feed pelas
    novas (o feed de origem já manda a lista completa atual a cada
    consulta, não incremental)."""
    with get_conn() as conn:
        conn.execute("DELETE FROM threat_feed_entries WHERE source = ?", (source,))
        conn.executemany(
            "INSERT INTO threat_feed_entries (source, value) VALUES (?, ?)",
            [(source, e) for e in entries],
        )


def get_all_feed_entries() -> list[tuple[str, str]]:
    """Retorna (source, value) de todas as entradas de todos os feeds."""
    with get_conn() as conn:
        return conn.execute("SELECT source, value FROM threat_feed_entries").fetchall()


def count_feed_entries_by_source() -> list[tuple[str, int, str]]:
    """Retorna (source, total, fetched_at mais recente) por fonte."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT source, COUNT(*), MAX(fetched_at) FROM threat_feed_entries GROUP BY source"
        ).fetchall()


def get_distinct_honeypot_ips_since(hours: float) -> list[str]:
    """Retorna os IPs distintos que tocaram algum honeypot nas últimas N
    horas — base para comparar fingerprints entre atacantes."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT DISTINCT ip FROM honeypot_hits WHERE timestamp >= datetime('now', ?)",
            (f"-{hours} hours",),
        ).fetchall()
        return [r[0] for r in rows]


def get_honeypot_hits_chronological_for_ip(ip: str) -> list[tuple[int, str, str]]:
    """Retorna (port, service, timestamp) de TODAS as conexões de um IP
    em ordem cronológica (mais antiga primeiro) — base para construir o
    fingerprint comportamental (sequência de portas + timing)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT port, service, timestamp FROM honeypot_hits WHERE ip = ? ORDER BY id ASC",
            (ip,),
        ).fetchall()


def plant_honeytoken(token_id: str, kind: str, location: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO honeytokens (token_id, kind, location) VALUES (?, ?, ?)",
            (token_id, kind, location),
        )


def record_honeytoken_trigger(token_id: str, source_ip: str | None, user_agent: str | None) -> bool:
    """Registra um disparo de honeytoken. Retorna False se o token_id não
    existe (chamada espúria, ex: alguém adivinhando URLs), True se
    disparou de verdade."""
    with get_conn() as conn:
        exists = conn.execute(
            "SELECT 1 FROM honeytokens WHERE token_id = ?", (token_id,)
        ).fetchone()
        if not exists:
            return False
        conn.execute(
            "INSERT INTO honeytoken_triggers (token_id, source_ip, user_agent) VALUES (?, ?, ?)",
            (token_id, source_ip, user_agent),
        )
        conn.execute(
            "UPDATE honeytokens SET triggered_count = triggered_count + 1, "
            "last_triggered_at = datetime('now') WHERE token_id = ?",
            (token_id,),
        )
        return True


def list_honeytokens():
    """Retorna (token_id, kind, location, planted_at, triggered_count, last_triggered_at)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT token_id, kind, location, planted_at, triggered_count, last_triggered_at "
            "FROM honeytokens ORDER BY planted_at DESC"
        ).fetchall()


def get_honeytoken_triggers(token_id: str):
    """Retorna (source_ip, user_agent, timestamp) de todos os disparos de um token."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT source_ip, user_agent, timestamp FROM honeytoken_triggers "
            "WHERE token_id = ? ORDER BY id DESC",
            (token_id,),
        ).fetchall()


def declare_honeynet_range(cidr: str, description: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO honeynet_ranges (cidr, description) VALUES (?, ?) "
            "ON CONFLICT(cidr) DO UPDATE SET description = excluded.description",
            (cidr, description),
        )


def list_honeynet_ranges():
    """Retorna (cidr, description, declared_at)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT cidr, description, declared_at FROM honeynet_ranges ORDER BY declared_at"
        ).fetchall()


def remove_honeynet_range(cidr: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM honeynet_ranges WHERE cidr = ?", (cidr,))
        return cur.rowcount > 0


# ---------- rate limiting ----------

def record_rate_limited(ip: str, connections_per_second: int, reason: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO rate_limited_ips (ip, connections_per_second, reason) "
            "VALUES (?, ?, ?)",
            (ip, connections_per_second, reason),
        )


def remove_rate_limited(ip: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM rate_limited_ips WHERE ip = ?", (ip,))


def list_rate_limited_ips():
    """Retorna (ip, connections_per_second, rate_limited_at, reason)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT ip, connections_per_second, rate_limited_at, reason "
            "FROM rate_limited_ips ORDER BY rate_limited_at DESC"
        ).fetchall()


def get_rate_limited(ip: str):
    """Retorna (connections_per_second, rate_limited_at, reason) ou None."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT connections_per_second, rate_limited_at, reason "
            "FROM rate_limited_ips WHERE ip = ?",
            (ip,),
        ).fetchone()


# ---------- playbook executions ----------

def record_playbook_execution(ip: str, attack_type: str, level_reached: int, actions: list):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO playbook_executions (ip, attack_type, level_reached, actions_json) "
            "VALUES (?, ?, ?, ?)",
            (ip, attack_type, level_reached, json.dumps(actions)),
        )


def list_playbook_executions(ip: str | None = None, limit: int = 20):
    """Retorna (ip, attack_type, level_reached, actions_json, triggered_at)."""
    with get_conn() as conn:
        if ip:
            return conn.execute(
                "SELECT ip, attack_type, level_reached, actions_json, triggered_at "
                "FROM playbook_executions WHERE ip = ? ORDER BY triggered_at DESC LIMIT ?",
                (ip, limit),
            ).fetchall()
        return conn.execute(
            "SELECT ip, attack_type, level_reached, actions_json, triggered_at "
            "FROM playbook_executions ORDER BY triggered_at DESC LIMIT ?",
            (limit,),
        ).fetchall()


# ---------- ASN blocks ----------

def record_asn_block(asn: str, description: str, prefixes: list):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO asn_blocks (asn, description, prefixes_json, prefix_count) "
            "VALUES (?, ?, ?, ?)",
            (asn, description, json.dumps(prefixes), len(prefixes)),
        )


def remove_asn_block(asn: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM asn_blocks WHERE asn = ?", (asn,))
        return cur.rowcount > 0


def list_asn_blocks():
    """Retorna (asn, description, prefix_count, blocked_at)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT asn, description, prefix_count, blocked_at FROM asn_blocks ORDER BY blocked_at DESC"
        ).fetchall()


def get_asn_block(asn: str):
    """Retorna (description, prefixes_json, blocked_at) ou None."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT description, prefixes_json, blocked_at FROM asn_blocks WHERE asn = ?",
            (asn,),
        ).fetchone()


# ---------- infrastructure map ----------

def add_ip_block(cidr: str, description: str, is_critical: bool, asn: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO infrastructure_ip_blocks "
            "(cidr, description, is_critical, asn) VALUES (?, ?, ?, ?)",
            (cidr, description, int(is_critical), asn),
        )


def remove_ip_block(cidr: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM infrastructure_ip_blocks WHERE cidr = ?", (cidr,))


def list_ip_blocks():
    """Retorna (cidr, description, is_critical, asn, added_at)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT cidr, description, is_critical, asn, added_at "
            "FROM infrastructure_ip_blocks ORDER BY added_at"
        ).fetchall()


def add_infrastructure_asn(asn: str, description: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO infrastructure_asns (asn, description) VALUES (?, ?)",
            (asn, description),
        )


def remove_infrastructure_asn(asn: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM infrastructure_asns WHERE asn = ?", (asn,))


def list_infrastructure_asns():
    """Retorna (asn, description, added_at)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT asn, description, added_at FROM infrastructure_asns ORDER BY added_at"
        ).fetchall()


def add_topology_node(name: str, node_type: str, ip_or_cidr: str, description: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO infrastructure_nodes "
            "(name, node_type, ip_or_cidr, description) VALUES (?, ?, ?, ?)",
            (name, node_type, ip_or_cidr, description),
        )


def remove_topology_node(name: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM infrastructure_nodes WHERE name = ?", (name,))


def list_topology_nodes():
    """Retorna (name, node_type, ip_or_cidr, description, added_at)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT name, node_type, ip_or_cidr, description, added_at "
            "FROM infrastructure_nodes ORDER BY node_type, name"
        ).fetchall()


# ---------- asset inventory ----------

def upsert_asset(ip: str, hostname: str, open_ports_json: str,
                  os_guess: str) -> tuple[bool, list]:
    """Insere ou atualiza um ativo. Retorna (is_new, [(change_type, old, new)])."""
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT hostname, open_ports_json, os_guess FROM asset_inventory WHERE ip = ?",
            (ip,),
        ).fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO asset_inventory (ip, hostname, open_ports_json, os_guess) "
                "VALUES (?, ?, ?, ?)",
                (ip, hostname, open_ports_json, os_guess),
            )
            return True, []
        changes = []
        old_hostname, old_ports_json, old_os = existing
        if hostname and hostname != old_hostname:
            changes.append(("hostname", old_hostname, hostname))
        if open_ports_json != old_ports_json:
            changes.append(("portas", old_ports_json, open_ports_json))
        if os_guess and os_guess != old_os:
            changes.append(("os_guess", old_os, os_guess))
        conn.execute(
            "UPDATE asset_inventory SET hostname = ?, open_ports_json = ?, "
            "os_guess = ?, last_seen = datetime('now') WHERE ip = ?",
            (hostname or old_hostname, open_ports_json, os_guess or old_os, ip),
        )
        return False, changes


def list_assets():
    """Retorna (ip, hostname, open_ports_json, os_guess, first_seen, last_seen, status)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT ip, hostname, open_ports_json, os_guess, first_seen, last_seen, status "
            "FROM asset_inventory ORDER BY ip"
        ).fetchall()


def record_asset_change(ip: str, change_type: str, old_value: str, new_value: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO asset_changes (ip, change_type, old_value, new_value) "
            "VALUES (?, ?, ?, ?)",
            (ip, change_type, old_value, new_value),
        )


def list_asset_changes(limit: int = 50):
    """Retorna (ip, change_type, old_value, new_value, detected_at)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT ip, change_type, old_value, new_value, detected_at "
            "FROM asset_changes ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()


# ---------- client baselines ----------

def add_client_profile(client_id: str, cidr: str, description: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO client_profiles (client_id, cidr, description) "
            "VALUES (?, ?, ?)",
            (client_id, cidr, description),
        )


def remove_client_profile(client_id: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM client_profiles WHERE client_id = ?", (client_id,))


def list_client_profiles():
    """Retorna (client_id, cidr, description, added_at)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT client_id, cidr, description, added_at "
            "FROM client_profiles ORDER BY client_id"
        ).fetchall()


def get_client_profile(client_id: str):
    """Retorna (client_id, cidr, description, added_at) ou None."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT client_id, cidr, description, added_at "
            "FROM client_profiles WHERE client_id = ?",
            (client_id,),
        ).fetchone()


def record_client_traffic_sample(client_id: str, hour_of_day: int, day_of_week: int,
                                   total_connections: int, distinct_ips: int):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO client_traffic_samples "
            "(client_id, hour_of_day, day_of_week, total_connections, distinct_ips) "
            "VALUES (?, ?, ?, ?, ?)",
            (client_id, hour_of_day, day_of_week, total_connections, distinct_ips),
        )


def get_client_traffic_samples_for_slot(client_id: str, hour_of_day: int, day_of_week: int):
    """Retorna lista de (total_connections, distinct_ips) para o slot horário dado."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT total_connections, distinct_ips FROM client_traffic_samples "
            "WHERE client_id = ? AND hour_of_day = ? AND day_of_week = ? "
            "ORDER BY id DESC LIMIT 200",
            (client_id, hour_of_day, day_of_week),
        ).fetchall()


# ---------- DNS servers (monitoramento de resolvers) ----------

def add_dns_server(ip: str, hostname: str = "", description: str = ""):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO dns_servers (ip, hostname, description) "
            "VALUES (?, ?, ?)",
            (ip, hostname, description),
        )


def remove_dns_server(ip: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM dns_servers WHERE ip = ?", (ip,))


def list_dns_servers():
    """Retorna (ip, hostname, description, added_at)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT ip, hostname, description, added_at "
            "FROM dns_servers ORDER BY ip"
        ).fetchall()


def record_dns_health_check(ip: str, reachable: bool, latency_ms: int,
                            query_status: str, open_ports_json: str,
                            risky_ports_json: str, cert_days_left,
                            problems_json: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO dns_health_checks "
            "(ip, reachable, latency_ms, query_status, open_ports_json, "
            "risky_ports_json, cert_days_left, problems_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ip, 1 if reachable else 0, latency_ms, query_status,
             open_ports_json, risky_ports_json, cert_days_left, problems_json),
        )


def list_dns_health_checks(ip: str | None = None, limit: int = 20):
    """Retorna (ip, reachable, latency_ms, query_status, open_ports_json,
    risky_ports_json, cert_days_left, problems_json, checked_at)."""
    with get_conn() as conn:
        if ip:
            return conn.execute(
                "SELECT ip, reachable, latency_ms, query_status, open_ports_json, "
                "risky_ports_json, cert_days_left, problems_json, checked_at "
                "FROM dns_health_checks WHERE ip = ? ORDER BY id DESC LIMIT ?",
                (ip, limit),
            ).fetchall()
        return conn.execute(
            "SELECT ip, reachable, latency_ms, query_status, open_ports_json, "
            "risky_ports_json, cert_days_left, problems_json, checked_at "
            "FROM dns_health_checks ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
