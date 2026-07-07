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
    user_agent TEXT,
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

CREATE TABLE IF NOT EXISTS decoy_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    decoy_id TEXT NOT NULL UNIQUE,
    hostname TEXT NOT NULL,
    ip TEXT NOT NULL,
    os TEXT NOT NULL,
    profile TEXT NOT NULL,
    services TEXT NOT NULL,
    lure_level TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    consumed_count INTEGER NOT NULL DEFAULT 0,
    last_consumed_at TEXT
);

CREATE TABLE IF NOT EXISTS malware_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL UNIQUE,
    filename TEXT NOT NULL,
    md5 TEXT,
    sha1 TEXT,
    size INTEGER,
    file_type TEXT,
    submitted_at TEXT NOT NULL DEFAULT (datetime('now')),
    detonated INTEGER NOT NULL DEFAULT 0,
    detonated_at TEXT,
    verdict TEXT
);

CREATE TABLE IF NOT EXISTS malware_iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    extracted_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(sha256, ioc_type, value)
);

CREATE INDEX IF NOT EXISTS idx_malware_iocs_sha ON malware_iocs(sha256);

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

CREATE TABLE IF NOT EXISTS brbos_rpz_blocks (
    domain TEXT PRIMARY KEY,
    action TEXT NOT NULL DEFAULT 'block',
    policy TEXT NOT NULL DEFAULT 'nxdomain',
    reason TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS brbos_dns_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    raw_json TEXT NOT NULL DEFAULT '{}',
    total_req INTEGER,
    hit INTEGER,
    miss INTEGER,
    nxdomain INTEGER,
    collected_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_brbos_dns_stats_host ON brbos_dns_stats(host);

-- Memória institucional de longo prazo (Fase 7, item 1): fatos/decisões
-- duráveis que sobrevivem entre sessões e são recuperados por relevância
-- (FTS5), distinta da janela rolante de conversa (tabela `conversation`).
CREATE TABLE IF NOT EXISTS memory_facts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL,
    category TEXT NOT NULL DEFAULT 'fact',
    content TEXT NOT NULL,
    importance INTEGER NOT NULL DEFAULT 3,
    source TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1,
    recall_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_recalled_at TEXT
);

CREATE VIRTUAL TABLE IF NOT EXISTS memory_facts_fts USING fts5(
    content, slug, category, content='memory_facts', content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS memory_facts_ai AFTER INSERT ON memory_facts BEGIN
    INSERT INTO memory_facts_fts(rowid, content, slug, category) VALUES (new.id, new.content, new.slug, new.category);
END;

CREATE TRIGGER IF NOT EXISTS memory_facts_ad AFTER DELETE ON memory_facts BEGIN
    INSERT INTO memory_facts_fts(memory_facts_fts, rowid, content, slug, category) VALUES ('delete', old.id, old.content, old.slug, old.category);
END;

CREATE TRIGGER IF NOT EXISTS memory_facts_au AFTER UPDATE ON memory_facts BEGIN
    INSERT INTO memory_facts_fts(memory_facts_fts, rowid, content, slug, category) VALUES ('delete', old.id, old.content, old.slug, old.category);
    INSERT INTO memory_facts_fts(rowid, content, slug, category) VALUES (new.id, new.content, new.slug, new.category);
END;

-- Auto-ajuste de thresholds (Fase 7, item 4): rótulos do operador sobre os
-- alertas (falso positivo / verdadeiro positivo / detecção perdida) — é a
-- verdade-terreno a partir da qual a Nexus aprende a calibrar sozinha.
CREATE TABLE IF NOT EXISTS alert_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'global',
    label TEXT NOT NULL,            -- 'fp' | 'tp' | 'missed'
    z_score REAL,
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_alert_feedback_scope ON alert_feedback(alert_type, scope);

-- Thresholds aprendidos por (alert_type, scope). Override BOUNDED do base: a
-- detecção lê este valor (sempre re-clampado no piso/teto) em vez do default.
CREATE TABLE IF NOT EXISTS tuned_thresholds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'global',
    threshold REAL NOT NULL,
    base REAL NOT NULL,
    samples_at_tune INTEGER NOT NULL DEFAULT 0,
    reason TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(alert_type, scope)
);

-- Operação de ISP / NOC (Fase 8): assinantes gerenciados, equipamentos
-- monitorados e chamados de queda. Distinto de client_profiles (baseline de
-- tráfego por CIDR) — aqui o foco é cobrança/bloqueio e uptime de hardware.

-- Assinantes gerenciados (clientes finais com IP + roteador de borda). A
-- fonte local de cobrança mora aqui (invoice_status/days_overdue); um
-- adaptador externo pode sobrescrever esses campos no futuro.
CREATE TABLE IF NOT EXISTS subscribers (
    subscriber_id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL,
    device_host TEXT NOT NULL DEFAULT '',   -- IP/host do MikroTik que controla o assinante
    interface TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'ativo',    -- 'ativo' | 'bloqueado_inadimplencia'
    invoice_status TEXT NOT NULL DEFAULT 'em_dia',  -- 'em_dia' | 'pendente'
    days_overdue INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Auditoria de cada bloqueio/desbloqueio de assinante (equivale a
-- logs_automacao do spec). A trilha hash-chain em `events` também registra.
CREATE TABLE IF NOT EXISTS subscriber_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subscriber_id TEXT NOT NULL,
    action TEXT NOT NULL,        -- 'bloqueado' | 'desbloqueado' | 'bloqueio_recusado' | ...
    reason TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_subscriber_actions_sub ON subscriber_actions(subscriber_id);

-- Equipamentos monitorados por ping (Microkit/OLT/switch). O estado atual
-- fica persistido (current_status) para o monitor não depender de um set em
-- memória — sobrevive a restart (corrige o bug do spec).
CREATE TABLE IF NOT EXISTS monitored_devices (
    device_id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL,
    model TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL DEFAULT 'mikrotik',   -- 'mikrotik' | 'olt' | 'switch'
    enabled INTEGER NOT NULL DEFAULT 1,
    current_status TEXT NOT NULL DEFAULT 'unknown',  -- 'online' | 'offline' | 'unknown'
    last_change_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Chamados de queda de equipamento (equivale a alertas_rede do spec).
CREATE TABLE IF NOT EXISTS device_outages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'aberto',   -- 'aberto' | 'resolvido'
    opened_at TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_device_outages_dev ON device_outages(device_id);

-- Cursor de encaminhamento ao SIEM (Frente I): id do último evento já enviado,
-- para o forward ser incremental (linha única, id fixo = 1).
CREATE TABLE IF NOT EXISTS siem_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_event_id INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Inventário de ativos AUTORIZADOS (Control Plane / Prioridade 3). Distinto de
-- `authorized_assets` (agendamento de auditoria proativa) e de `assets`
-- (descoberta automática por scan): aqui ficam os ativos que um operador
-- autorizou explicitamente como alvo de ação sensível, com escopo, ambiente
-- (real/lab) e janela de validade. Sem um ativo habilitado e no escopo, uma
-- ação sensível NÃO executa.
CREATE TABLE IF NOT EXISTS asset_registry (
    asset_id TEXT PRIMARY KEY,
    asset_type TEXT NOT NULL,                    -- network|host|mikrotik|subscriber|server|sensor|honeypot|lab
    hostname TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    cidr TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL DEFAULT '',
    environment TEXT NOT NULL DEFAULT 'real',    -- real|lab
    authorized_scope TEXT NOT NULL DEFAULT '',   -- csv de ações permitidas, ou '*'
    valid_from TEXT,
    valid_until TEXT,
    notes TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_asset_registry_ip ON asset_registry(ip);

-- Estado de runtime do sistema (chave/valor). Fonte da verdade do MODO
-- OPERACIONAL do backend (real|lab|replay) — independente do modo VISUAL do
-- cliente Tauri, que é só localStorage do cliente e não trafega. Default vem
-- de config.NEXUS_OPERATING_MODE; um operador pode sobrescrever em runtime.
CREATE TABLE IF NOT EXISTS system_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Usuários da API REST (Fase 3 — RBAC rico). Identidade real por trás de cada
-- token: id + nome + papel (rbac.ROLES) + token HASHEADO (sha256). O valor cru
-- do token NUNCA é gravado (só o hash e uma dica p/ identificar). O api/server
-- resolve token->papel AQUI depois do token principal e dos NEXUS_ROLE_TOKENS do
-- .env (compatível). enabled=0 + revoked_at revoga o acesso.
CREATE TABLE IF NOT EXISTS api_users (
    user_id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'readonly',
    token_hash TEXT NOT NULL,
    token_hint TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_api_users_token_hash ON api_users(token_hash);

-- Casos / incidentes (Prioridade 6). Fundação de incident management: agrega
-- evidências, timeline, ações tomadas e eventos relacionados num caso com
-- ciclo de vida (open→investigating→contained→resolved|false_positive). Campos
-- de lista (event_ids/timeline/evidence/actions_taken) são JSON. O rótulo
-- público é derivado do id (INC-0001) na camada tools/incidents.
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'open',
    owner TEXT NOT NULL DEFAULT '',
    related_ip TEXT NOT NULL DEFAULT '',
    related_asset TEXT NOT NULL DEFAULT '',
    event_ids TEXT NOT NULL DEFAULT '[]',
    timeline TEXT NOT NULL DEFAULT '[]',
    evidence TEXT NOT NULL DEFAULT '[]',
    actions_taken TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

-- Assinaturas HMAC dos eventos (Prioridade 7) — canal LATERAL. NÃO altera a
-- tabela events nem _compute_entry_hash: cada linha guarda o HMAC do entry_hash
-- de um evento, assinado com AUDIT_HMAC_SECRET. Dá autenticidade (prova de que a
-- cadeia foi produzida por quem tem o segredo) por cima da integridade da hash
-- chain. Eventos antigos continuam válidos mesmo sem assinatura.
CREATE TABLE IF NOT EXISTS event_signatures (
    event_id INTEGER PRIMARY KEY,
    signature TEXT NOT NULL,
    algo TEXT NOT NULL DEFAULT 'hmac-sha256',
    signed_at TEXT NOT NULL DEFAULT (datetime('now'))
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
        try:
            conn.execute("ALTER TABLE honeypot_hits ADD COLUMN user_agent TEXT")
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
        # CP-SD Fase 6K: bookkeeping de cooldown de reavaliação SIEM (não faz
        # parte da hash chain — `siem_state` nunca teve prev_hash/entry_hash).
        for column in (
            "last_blocked_action_type TEXT",
            "last_blocked_decision TEXT",
            "last_blocked_mode TEXT",
            "last_blocked_actor TEXT",
            "last_blocked_role TEXT",
            "last_blocked_at TEXT",
        ):
            try:
                conn.execute(f"ALTER TABLE siem_state ADD COLUMN {column}")
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


def get_events_after_id(last_id: int, limit: int = 500):
    """Retorna (id, timestamp, event_type, source_ip, detail, action_taken) dos
    eventos com id > last_id, em ordem — base do encaminhamento incremental ao
    SIEM (Frente I)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT id, timestamp, event_type, source_ip, detail, action_taken FROM events "
            "WHERE id > ? ORDER BY id ASC LIMIT ?",
            (last_id, limit),
        ).fetchall()


def get_siem_cursor() -> int:
    with get_conn() as conn:
        row = conn.execute("SELECT last_event_id FROM siem_state WHERE id = 1").fetchone()
    return row[0] if row else 0


def set_siem_cursor(last_event_id: int) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO siem_state (id, last_event_id, updated_at) "
            "VALUES (1, ?, datetime('now')) "
            "ON CONFLICT(id) DO UPDATE SET last_event_id = excluded.last_event_id, "
            "updated_at = datetime('now')",
            (last_event_id,),
        )


def get_siem_blocked_state() -> dict | None:
    """Estado da ÚLTIMA decisão DENY/DRY_RUN_ONLY de `siem.forward_events`
    (CP-SD Fase 6K) — usado por `tools/siem.py` para decidir se pode pular
    reavaliação dentro do cooldown. `None` = nenhum bloqueio registrado (ou
    já foi limpo por um ALLOW). Não faz parte da hash chain."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT last_blocked_action_type, last_blocked_decision, last_blocked_mode, "
            "last_blocked_actor, last_blocked_role, last_blocked_at "
            "FROM siem_state WHERE id = 1"
        ).fetchone()
    if not row or row[5] is None:
        return None
    return {
        "action_type": row[0], "decision": row[1], "mode": row[2],
        "actor": row[3], "role": row[4], "blocked_at": row[5],
    }


def set_siem_blocked_state(action_type: str, decision: str, mode: str, actor: str,
                            role: str, blocked_at: str) -> None:
    """Registra que a última tentativa de `siem.forward_events` foi negada
    (DENY) ou virou DRY_RUN_ONLY, com a identidade/modo daquele momento —
    NUNCA mexe em `last_event_id` (cursor) nem em `events`."""
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO siem_state (id, last_event_id, last_blocked_action_type, "
            "last_blocked_decision, last_blocked_mode, last_blocked_actor, "
            "last_blocked_role, last_blocked_at, updated_at) "
            "VALUES (1, 0, ?, ?, ?, ?, ?, ?, datetime('now')) "
            "ON CONFLICT(id) DO UPDATE SET "
            "last_blocked_action_type = excluded.last_blocked_action_type, "
            "last_blocked_decision = excluded.last_blocked_decision, "
            "last_blocked_mode = excluded.last_blocked_mode, "
            "last_blocked_actor = excluded.last_blocked_actor, "
            "last_blocked_role = excluded.last_blocked_role, "
            "last_blocked_at = excluded.last_blocked_at, "
            "updated_at = datetime('now')",
            (action_type, decision, mode, actor, role, blocked_at),
        )


def clear_siem_blocked_state() -> None:
    """Limpa o bookkeeping de bloqueio (chamado quando `siem.forward_events`
    volta a ALLOW) — não afeta o cursor (`last_event_id`)."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE siem_state SET last_blocked_action_type = NULL, "
            "last_blocked_decision = NULL, last_blocked_mode = NULL, "
            "last_blocked_actor = NULL, last_blocked_role = NULL, "
            "last_blocked_at = NULL, updated_at = datetime('now') WHERE id = 1"
        )


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


# ---------- Memória institucional de longo prazo (Fase 7, item 1) ----------

def upsert_memory_fact(slug: str, category: str, content: str,
                       importance: int = 3, source: str = "") -> str:
    """Insere ou atualiza (pela slug) um fato durável. Reativa se estava
    esquecido. Retorna 'created' ou 'updated'."""
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT id FROM memory_facts WHERE slug = ?", (slug,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE memory_facts SET category=?, content=?, importance=?, "
                "source=?, active=1, updated_at=datetime('now') WHERE slug=?",
                (category, content, importance, source, slug),
            )
            return "updated"
        conn.execute(
            "INSERT INTO memory_facts (slug, category, content, importance, source) "
            "VALUES (?, ?, ?, ?, ?)",
            (slug, category, content, importance, source),
        )
        return "created"


def search_memory_facts(query: str, limit: int = 8):
    """Busca full-text nos fatos ativos. Retorna (slug, category, content,
    importance, snippet) por relevância. Termos combinados com OR, cada um
    como frase exata sanitizada (mesma proteção de search_knowledge)."""
    terms = [t.replace('"', '""') for t in query.split() if t.strip()]
    if not terms:
        return []
    match_expr = " OR ".join(f'"{t}"' for t in terms)
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT mf.slug, mf.category, mf.content, mf.importance,
                   snippet(memory_facts_fts, 0, '>>', '<<', '...', 40) as snippet
            FROM memory_facts_fts
            JOIN memory_facts mf ON mf.id = memory_facts_fts.rowid
            WHERE memory_facts_fts MATCH ? AND mf.active = 1
            ORDER BY rank
            LIMIT ?
            """,
            (match_expr, limit),
        ).fetchall()


def list_memory_facts(category: str | None = None,
                      include_inactive: bool = False, limit: int = 200):
    """Lista fatos (slug, category, content, importance, source, active,
    recall_count, created_at, updated_at), mais importantes/recentes primeiro."""
    conds, params = [], []
    if not include_inactive:
        conds.append("active = 1")
    if category:
        conds.append("category = ?")
        params.append(category)
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    params.append(limit)
    with get_conn() as conn:
        return conn.execute(
            "SELECT slug, category, content, importance, source, active, "
            "recall_count, created_at, updated_at FROM memory_facts"
            + where + " ORDER BY importance DESC, updated_at DESC LIMIT ?",
            tuple(params),
        ).fetchall()


def get_top_memory_facts(limit: int = 12):
    """Os fatos ativos mais importantes/recentes — p/ injetar no contexto de
    cada sessão. Retorna (slug, category, content, importance)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT slug, category, content, importance FROM memory_facts "
            "WHERE active = 1 ORDER BY importance DESC, updated_at DESC LIMIT ?",
            (limit,),
        ).fetchall()


def get_memory_fact(slug: str):
    """Retorna o fato completo por slug, ou None."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT slug, category, content, importance, source, active, "
            "recall_count, created_at, updated_at, last_recalled_at "
            "FROM memory_facts WHERE slug = ?",
            (slug,),
        ).fetchone()


def forget_memory_fact(slug: str) -> bool:
    """Soft-delete: desativa um fato ativo. True se existia e estava ativo."""
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE memory_facts SET active=0, updated_at=datetime('now') "
            "WHERE slug=? AND active=1",
            (slug,),
        )
        return cur.rowcount > 0


def touch_memory_recall(slugs) -> None:
    """Marca fatos como recém-recuperados (recall_count++ + timestamp)."""
    slugs = list(slugs)
    if not slugs:
        return
    with get_conn() as conn:
        conn.executemany(
            "UPDATE memory_facts SET recall_count = recall_count + 1, "
            "last_recalled_at = datetime('now') WHERE slug = ?",
            [(s,) for s in slugs],
        )


def count_memory_facts(active_only: bool = True) -> int:
    with get_conn() as conn:
        q = "SELECT COUNT(*) FROM memory_facts"
        if active_only:
            q += " WHERE active = 1"
        return conn.execute(q).fetchone()[0]


def count_memory_facts_by_category(active_only: bool = True):
    """Retorna (category, total) agrupado, p/ o panorama da memória."""
    with get_conn() as conn:
        q = "SELECT category, COUNT(*) FROM memory_facts"
        if active_only:
            q += " WHERE active = 1"
        q += " GROUP BY category ORDER BY category"
        return conn.execute(q).fetchall()


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


def record_honeypot_hit(ip: str, port: int, service: str = "ssh", user_agent: str | None = None):
    """Registra que um IP conectou na porta-armadilha — diferente da
    detecção por volume de tráfego, isto é praticamente prova direta de
    varredura/ataque, já que nenhum cliente legítimo deveria conectar
    nessa porta. user_agent (quando o serviço é HTTP e o atacante mandou o
    header) alimenta o fingerprint da ferramenta (tools/tool_fingerprint.py)."""
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO honeypot_hits (ip, port, service, user_agent) VALUES (?, ?, ?, ?)",
            (ip, port, service, user_agent or None),
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


def get_honeypot_hit_counts_by_ip():
    """Retorna (ip, total_hits) agrupado por IP — para agregar atividade de
    honeypot por bloco de cliente (modelo de risco por cliente, Fase 7)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT ip, COUNT(*) FROM honeypot_hits GROUP BY ip"
        ).fetchall()


# --- Auto-ajuste de thresholds (Fase 7, item 4) ---

def record_alert_feedback(alert_type: str, scope: str, label: str,
                          z_score: float | None = None, note: str = ""):
    """Persiste o rótulo do operador sobre um alerta (fp/tp/missed) — a
    verdade-terreno do auto-ajuste de thresholds."""
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO alert_feedback (alert_type, scope, label, z_score, note) "
            "VALUES (?, ?, ?, ?, ?)",
            (alert_type, scope, label, z_score, note),
        )


def get_alert_feedback_counts(alert_type: str, scope: str):
    """Retorna [(label, count)] dos rótulos de um (alert_type, scope)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT label, COUNT(*) FROM alert_feedback "
            "WHERE alert_type = ? AND scope = ? GROUP BY label",
            (alert_type, scope),
        ).fetchall()


def list_alert_feedback(alert_type: str | None = None, scope: str | None = None,
                        limit: int = 200):
    """Lista feedbacks (mais recentes primeiro), filtráveis por tipo/escopo."""
    q = ("SELECT alert_type, scope, label, z_score, note, created_at "
         "FROM alert_feedback")
    clauses, params = [], []
    if alert_type is not None:
        clauses.append("alert_type = ?")
        params.append(alert_type)
    if scope is not None:
        clauses.append("scope = ?")
        params.append(scope)
    if clauses:
        q += " WHERE " + " AND ".join(clauses)
    q += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with get_conn() as conn:
        return conn.execute(q, params).fetchall()


def upsert_tuned_threshold(alert_type: str, scope: str, threshold: float,
                           base: float, samples_at_tune: int = 0, reason: str = ""):
    """Grava/atualiza o threshold aprendido de um (alert_type, scope)."""
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO tuned_thresholds
                (alert_type, scope, threshold, base, samples_at_tune, reason, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(alert_type, scope) DO UPDATE SET
                threshold = excluded.threshold,
                base = excluded.base,
                samples_at_tune = excluded.samples_at_tune,
                reason = excluded.reason,
                updated_at = datetime('now')
            """,
            (alert_type, scope, threshold, base, samples_at_tune, reason),
        )


def get_tuned_threshold(alert_type: str, scope: str):
    """Retorna (threshold, base, samples_at_tune, reason, updated_at) ou None."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT threshold, base, samples_at_tune, reason, updated_at "
            "FROM tuned_thresholds WHERE alert_type = ? AND scope = ?",
            (alert_type, scope),
        ).fetchone()


def list_tuned_thresholds():
    """Lista todos os thresholds aprendidos."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT alert_type, scope, threshold, base, samples_at_tune, reason, updated_at "
            "FROM tuned_thresholds ORDER BY alert_type, scope"
        ).fetchall()


def delete_tuned_threshold(alert_type: str, scope: str) -> bool:
    """Remove o override de um (alert_type, scope), revertendo ao base. True
    se algo foi removido."""
    with get_conn() as conn:
        cur = conn.execute(
            "DELETE FROM tuned_thresholds WHERE alert_type = ? AND scope = ?",
            (alert_type, scope),
        )
        return cur.rowcount > 0


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


def get_attacker_user_agents_for_ip(ip: str) -> list[str]:
    """Retorna os User-Agents não-vazios que um IP já apresentou em disparos
    de honeytoken — sinal para fingerprint da ferramenta do atacante
    (tools/tool_fingerprint.py). Fonte: honeytoken_triggers. Para os UAs vistos
    no honeypot HTTP, ver get_honeypot_user_agents_for_ip (Fase 6, fatia 2B)."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT user_agent FROM honeytoken_triggers "
            "WHERE source_ip = ? AND user_agent IS NOT NULL AND user_agent != '' "
            "ORDER BY id DESC",
            (ip,),
        ).fetchall()
        return [r[0] for r in rows]


def get_honeypot_user_agents_for_ip(ip: str) -> list[str]:
    """Retorna os User-Agents distintos não-vazios que um IP apresentou no
    honeypot HTTP (Fase 6, fatia 2B). Complementa get_attacker_user_agents_for_ip
    (honeytoken) como fonte do fingerprint da ferramenta do atacante. Mantém a
    ordem de chegada mais recente primeiro, sem repetir."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT user_agent FROM honeypot_hits "
            "WHERE ip = ? AND user_agent IS NOT NULL AND user_agent != '' "
            "ORDER BY id DESC",
            (ip,),
        ).fetchall()
    seen, result = set(), []
    for (ua,) in rows:
        if ua not in seen:
            seen.add(ua)
            result.append(ua)
    return result


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


def get_traffic_slot_coverage():
    """Retorna [(hour_of_day, day_of_week, count)] de amostras por slot — base
    do relatório de maturidade da baseline global (quantos dos 168 slots
    semanais já têm histórico suficiente)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT hour_of_day, day_of_week, COUNT(*) FROM traffic_baseline_samples "
            "GROUP BY hour_of_day, day_of_week"
        ).fetchall()


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


# ---------- deception ativa (decoy assets) ----------

def add_decoy_asset(decoy_id: str, hostname: str, ip: str, os: str,
                    profile: str, services_json: str, lure_level: str):
    """Registra um host-isca (decoy) da deception ativa. `services_json` é o
    JSON da lista de serviços/banners falsos. IP deve ser de espaço morto
    (honeynet) — a validação fica em tools/deception.py, não aqui."""
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO decoy_assets (decoy_id, hostname, ip, os, profile, services, lure_level) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (decoy_id, hostname, ip, os, profile, services_json, lure_level),
        )


def list_decoy_assets():
    """Retorna (decoy_id, hostname, ip, os, profile, services_json, lure_level,
    created_at, consumed_count, last_consumed_at)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT decoy_id, hostname, ip, os, profile, services, lure_level, "
            "created_at, consumed_count, last_consumed_at FROM decoy_assets "
            "ORDER BY created_at"
        ).fetchall()


def get_decoy_ips() -> set[str]:
    """Conjunto dos IPs atualmente ocupados por decoys (para alocar IP novo
    sem colisão)."""
    with get_conn() as conn:
        return {r[0] for r in conn.execute("SELECT ip FROM decoy_assets").fetchall()}


def remove_decoy_asset(decoy_id: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM decoy_assets WHERE decoy_id = ?", (decoy_id,))
        return cur.rowcount > 0


def record_decoy_consumption(ip: str) -> bool:
    """Marca que o decoy de IP `ip` foi consumido (alguém agiu sobre a
    informação falsa). Retorna True se havia um decoy nesse IP."""
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE decoy_assets SET consumed_count = consumed_count + 1, "
            "last_consumed_at = datetime('now') WHERE ip = ?",
            (ip,),
        )
        return cur.rowcount > 0


# ---------- sandbox de malware (amostras + IOCs) ----------

def add_malware_sample(sha256: str, filename: str, md5: str, sha1: str,
                       size: int, file_type: str):
    """Registra (ou atualiza metadados de) uma amostra submetida à sandbox.
    Chave é o sha256 — reenviar o mesmo arquivo não duplica."""
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO malware_samples (sha256, filename, md5, sha1, size, file_type) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(sha256) DO UPDATE SET filename = excluded.filename, "
            "md5 = excluded.md5, sha1 = excluded.sha1, size = excluded.size, "
            "file_type = excluded.file_type",
            (sha256, filename, md5, sha1, size, file_type),
        )


def get_malware_sample(sha256: str):
    """Retorna (sha256, filename, md5, sha1, size, file_type, submitted_at,
    detonated, detonated_at, verdict) ou None."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT sha256, filename, md5, sha1, size, file_type, submitted_at, "
            "detonated, detonated_at, verdict FROM malware_samples WHERE sha256 = ?",
            (sha256,),
        ).fetchone()


def list_malware_samples():
    """Retorna (sha256, filename, file_type, submitted_at, detonated, verdict)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT sha256, filename, file_type, submitted_at, detonated, verdict "
            "FROM malware_samples ORDER BY submitted_at DESC"
        ).fetchall()


def mark_sample_detonated(sha256: str, verdict: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE malware_samples SET detonated = 1, detonated_at = datetime('now'), "
            "verdict = ? WHERE sha256 = ?",
            (verdict, sha256),
        )
        return cur.rowcount > 0


def add_malware_ioc(sha256: str, ioc_type: str, value: str, source: str):
    """Adiciona um IOC extraído de uma amostra. Ignora duplicata
    (mesma amostra + tipo + valor)."""
    with get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO malware_iocs (sha256, ioc_type, value, source) "
            "VALUES (?, ?, ?, ?)",
            (sha256, ioc_type, value, source),
        )


def list_malware_iocs(sha256: str):
    """Retorna (ioc_type, value, source) de uma amostra."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT ioc_type, value, source FROM malware_iocs WHERE sha256 = ? "
            "ORDER BY ioc_type, value",
            (sha256,),
        ).fetchall()


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


def get_client_traffic_slot_coverage(client_id: str):
    """Retorna [(hour_of_day, day_of_week, count)] das amostras de um cliente —
    base do relatório de maturidade da baseline daquele cliente."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT hour_of_day, day_of_week, COUNT(*) FROM client_traffic_samples "
            "WHERE client_id = ? GROUP BY hour_of_day, day_of_week",
            (client_id,),
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


# ---------- BrbOS (integração com o SO de DNS da BrByte) ----------

def record_brbos_rpz_action(domain: str, action: str = "block",
                            policy: str = "nxdomain", reason: str = ""):
    """Registra (auditoria local) um bloqueio de domínio aplicado via RPZ."""
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO brbos_rpz_blocks (domain, action, policy, reason) "
            "VALUES (?, ?, ?, ?)",
            (domain, action, policy, reason),
        )


def get_brbos_rpz_action(domain: str):
    """Retorna (domain, action, policy, reason, created_at) ou None."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT domain, action, policy, reason, created_at "
            "FROM brbos_rpz_blocks WHERE domain = ?",
            (domain,),
        ).fetchone()


def remove_brbos_rpz_action(domain: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM brbos_rpz_blocks WHERE domain = ?", (domain,))


def list_brbos_rpz_actions():
    """Retorna (domain, action, policy, reason, created_at) ordenado por data."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT domain, action, policy, reason, created_at "
            "FROM brbos_rpz_blocks ORDER BY created_at DESC"
        ).fetchall()


def record_brbos_dns_stats(host: str, raw_json: str, total_req=None,
                           hit=None, miss=None, nxdomain=None):
    """Grava um snapshot das estatísticas de DNS do BrbOS (série temporal
    para baseline/anomalia futura)."""
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO brbos_dns_stats "
            "(host, raw_json, total_req, hit, miss, nxdomain) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (host, raw_json, total_req, hit, miss, nxdomain),
        )


def list_brbos_dns_stats(host: str | None = None, limit: int = 50):
    """Retorna (host, raw_json, total_req, hit, miss, nxdomain, collected_at)."""
    with get_conn() as conn:
        if host:
            return conn.execute(
                "SELECT host, raw_json, total_req, hit, miss, nxdomain, collected_at "
                "FROM brbos_dns_stats WHERE host = ? ORDER BY id DESC LIMIT ?",
                (host, limit),
            ).fetchall()
        return conn.execute(
            "SELECT host, raw_json, total_req, hit, miss, nxdomain, collected_at "
            "FROM brbos_dns_stats ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()


# ---------- Operação de ISP / NOC (Fase 8): assinantes ----------

def add_subscriber(subscriber_id: str, ip_address: str, name: str = "",
                   device_host: str = "", interface: str = "",
                   invoice_status: str = "em_dia", days_overdue: int = 0):
    """Cadastra/atualiza um assinante gerenciado. INSERT OR REPLACE preserva o
    subscriber_id como chave; mexer no status fica a cargo das funções de
    bloqueio/cobrança, então aqui não tocamos em `status` ao reinserir."""
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT status FROM subscribers WHERE subscriber_id = ?", (subscriber_id,)
        ).fetchone()
        status = existing[0] if existing else "ativo"
        conn.execute(
            "INSERT OR REPLACE INTO subscribers "
            "(subscriber_id, name, ip_address, device_host, interface, status, "
            " invoice_status, days_overdue, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
            (subscriber_id, name, ip_address, device_host, interface, status,
             invoice_status, days_overdue),
        )


def remove_subscriber(subscriber_id: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM subscribers WHERE subscriber_id = ?", (subscriber_id,))


def list_subscribers(status: str | None = None):
    """Retorna (subscriber_id, name, ip_address, device_host, interface, status,
    invoice_status, days_overdue)."""
    cols = ("subscriber_id, name, ip_address, device_host, interface, status, "
            "invoice_status, days_overdue")
    with get_conn() as conn:
        if status:
            return conn.execute(
                f"SELECT {cols} FROM subscribers WHERE status = ? ORDER BY subscriber_id",
                (status,),
            ).fetchall()
        return conn.execute(
            f"SELECT {cols} FROM subscribers ORDER BY subscriber_id"
        ).fetchall()


def get_subscriber(subscriber_id: str):
    """Retorna (subscriber_id, name, ip_address, device_host, interface, status,
    invoice_status, days_overdue) ou None."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT subscriber_id, name, ip_address, device_host, interface, status, "
            "invoice_status, days_overdue FROM subscribers WHERE subscriber_id = ?",
            (subscriber_id,),
        ).fetchone()


def set_subscriber_invoice_status(subscriber_id: str, invoice_status: str, days_overdue: int = 0):
    with get_conn() as conn:
        conn.execute(
            "UPDATE subscribers SET invoice_status = ?, days_overdue = ?, "
            "updated_at = datetime('now') WHERE subscriber_id = ?",
            (invoice_status, days_overdue, subscriber_id),
        )


def set_subscriber_status(subscriber_id: str, status: str):
    """Atualiza só o estado de conexão (ativo / bloqueado_inadimplencia)."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE subscribers SET status = ?, updated_at = datetime('now') "
            "WHERE subscriber_id = ?",
            (status, subscriber_id),
        )


def list_delinquent_subscribers(min_days: int):
    """Assinantes com fatura pendente, atraso >= min_days e ainda ativos —
    candidatos a bloqueio. Retorna (subscriber_id, name, ip_address,
    device_host, interface, days_overdue)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT subscriber_id, name, ip_address, device_host, interface, days_overdue "
            "FROM subscribers WHERE invoice_status = 'pendente' AND days_overdue >= ? "
            "AND status = 'ativo' ORDER BY days_overdue DESC",
            (min_days,),
        ).fetchall()


def list_reactivatable_subscribers():
    """Assinantes bloqueados por inadimplência que já regularizaram (fatura em
    dia) — candidatos a desbloqueio. Retorna (subscriber_id, name, ip_address,
    device_host, interface)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT subscriber_id, name, ip_address, device_host, interface "
            "FROM subscribers WHERE status = 'bloqueado_inadimplencia' "
            "AND invoice_status = 'em_dia' ORDER BY subscriber_id"
        ).fetchall()


def record_subscriber_action(subscriber_id: str, action: str, reason: str = ""):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO subscriber_actions (subscriber_id, action, reason) "
            "VALUES (?, ?, ?)",
            (subscriber_id, action, reason),
        )


def list_subscriber_actions(subscriber_id: str | None = None, limit: int = 50):
    """Retorna (subscriber_id, action, reason, created_at)."""
    with get_conn() as conn:
        if subscriber_id:
            return conn.execute(
                "SELECT subscriber_id, action, reason, created_at FROM subscriber_actions "
                "WHERE subscriber_id = ? ORDER BY id DESC LIMIT ?",
                (subscriber_id, limit),
            ).fetchall()
        return conn.execute(
            "SELECT subscriber_id, action, reason, created_at FROM subscriber_actions "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()


# ---------- Operação de ISP / NOC (Fase 8): equipamentos monitorados ----------

def add_monitored_device(device_id: str, ip: str, name: str = "", model: str = "",
                         location: str = "", type: str = "mikrotik", enabled: bool = True):
    """Cadastra/atualiza um equipamento a monitorar. Preserva o estado atual
    (current_status/last_change_at) ao reinserir — o monitor é dono disso."""
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT current_status, last_change_at FROM monitored_devices WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        current_status, last_change_at = existing if existing else ("unknown", None)
        conn.execute(
            "INSERT OR REPLACE INTO monitored_devices "
            "(device_id, name, ip, model, location, type, enabled, current_status, last_change_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (device_id, name, ip, model, location, type, 1 if enabled else 0,
             current_status, last_change_at),
        )


def remove_monitored_device(device_id: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM monitored_devices WHERE device_id = ?", (device_id,))


def list_monitored_devices(only_enabled: bool = False):
    """Retorna (device_id, name, ip, model, location, type, enabled,
    current_status, last_change_at)."""
    cols = ("device_id, name, ip, model, location, type, enabled, "
            "current_status, last_change_at")
    with get_conn() as conn:
        if only_enabled:
            return conn.execute(
                f"SELECT {cols} FROM monitored_devices WHERE enabled = 1 ORDER BY device_id"
            ).fetchall()
        return conn.execute(
            f"SELECT {cols} FROM monitored_devices ORDER BY device_id"
        ).fetchall()


def get_monitored_device(device_id: str):
    """Retorna (device_id, name, ip, model, location, type, enabled,
    current_status, last_change_at) ou None."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT device_id, name, ip, model, location, type, enabled, "
            "current_status, last_change_at FROM monitored_devices WHERE device_id = ?",
            (device_id,),
        ).fetchone()


def set_device_status(device_id: str, status: str):
    with get_conn() as conn:
        conn.execute(
            "UPDATE monitored_devices SET current_status = ?, "
            "last_change_at = datetime('now') WHERE device_id = ?",
            (status, device_id),
        )


def open_device_outage(device_id: str, ip: str = "", name: str = "", reason: str = ""):
    """Abre um chamado de queda se ainda não houver um aberto para o device."""
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT id FROM device_outages WHERE device_id = ? AND status = 'aberto'",
            (device_id,),
        ).fetchone()
        if existing:
            return existing[0]
        cur = conn.execute(
            "INSERT INTO device_outages (device_id, ip, name, reason) VALUES (?, ?, ?, ?)",
            (device_id, ip, name, reason),
        )
        return cur.lastrowid


def resolve_device_outage(device_id: str):
    """Marca como resolvido o chamado aberto do device (se houver)."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE device_outages SET status = 'resolvido', resolved_at = datetime('now') "
            "WHERE device_id = ? AND status = 'aberto'",
            (device_id,),
        )


def list_device_outages(status: str | None = None, limit: int = 50):
    """Retorna (device_id, ip, name, reason, status, opened_at, resolved_at)."""
    cols = "device_id, ip, name, reason, status, opened_at, resolved_at"
    with get_conn() as conn:
        if status:
            return conn.execute(
                f"SELECT {cols} FROM device_outages WHERE status = ? ORDER BY id DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        return conn.execute(
            f"SELECT {cols} FROM device_outages ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()


# ---------------------------------------------------------------------------
# Inventário de ativos autorizados (Control Plane / Prioridade 3)
# ---------------------------------------------------------------------------

_ASSET_COLS = (
    "asset_id, asset_type, hostname, ip, cidr, owner, environment, "
    "authorized_scope, valid_from, valid_until, notes, enabled, created_at, updated_at"
)


def register_asset(
    asset_id: str, asset_type: str, *, hostname: str = "", ip: str = "", cidr: str = "",
    owner: str = "", environment: str = "real", authorized_scope: str = "",
    valid_from: str | None = None, valid_until: str | None = None,
    notes: str = "", enabled: bool = True,
) -> None:
    """Cria/atualiza (upsert) um ativo autorizado pelo asset_id."""
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO asset_registry
                (asset_id, asset_type, hostname, ip, cidr, owner, environment,
                 authorized_scope, valid_from, valid_until, notes, enabled, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(asset_id) DO UPDATE SET
                asset_type=excluded.asset_type, hostname=excluded.hostname,
                ip=excluded.ip, cidr=excluded.cidr, owner=excluded.owner,
                environment=excluded.environment, authorized_scope=excluded.authorized_scope,
                valid_from=excluded.valid_from, valid_until=excluded.valid_until,
                notes=excluded.notes, enabled=excluded.enabled, updated_at=datetime('now')
            """,
            (asset_id, asset_type, hostname, ip, cidr, owner, environment,
             authorized_scope, valid_from, valid_until, notes, 1 if enabled else 0),
        )


def get_asset(asset_id: str):
    with get_conn() as conn:
        return conn.execute(
            f"SELECT {_ASSET_COLS} FROM asset_registry WHERE asset_id = ?", (asset_id,)
        ).fetchone()


def list_registered_assets(enabled_only: bool = False):
    with get_conn() as conn:
        if enabled_only:
            return conn.execute(
                f"SELECT {_ASSET_COLS} FROM asset_registry WHERE enabled = 1 ORDER BY asset_id"
            ).fetchall()
        return conn.execute(
            f"SELECT {_ASSET_COLS} FROM asset_registry ORDER BY asset_id"
        ).fetchall()


def find_assets_by_ip(ip: str):
    """Ativos cujo campo ip bate exatamente (correspondência por CIDR é feita na
    camada tools/asset_registry, que entende ipaddress)."""
    with get_conn() as conn:
        return conn.execute(
            f"SELECT {_ASSET_COLS} FROM asset_registry WHERE ip = ? ORDER BY asset_id", (ip,)
        ).fetchall()


def set_asset_enabled(asset_id: str, enabled: bool) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE asset_registry SET enabled = ?, updated_at = datetime('now') WHERE asset_id = ?",
            (1 if enabled else 0, asset_id),
        )
        return cur.rowcount > 0


def remove_asset(asset_id: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM asset_registry WHERE asset_id = ?", (asset_id,))
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Estado de runtime do sistema (modo operacional do backend, etc.)
# ---------------------------------------------------------------------------

def get_system_state(key: str, default: str = "") -> str:
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM system_state WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def set_system_state(key: str, value: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO system_state (key, value, updated_at) VALUES (?, ?, datetime('now')) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')",
            (key, value),
        )


# ---------------------------------------------------------------------------
# Usuários da API REST (Fase 3 — RBAC rico). O token cru NUNCA entra aqui:
# o chamador passa o hash. Leitura devolve metadados, nunca o hash nem o token.
# ---------------------------------------------------------------------------

_API_USER_COLS = "user_id, name, role, token_hint, enabled, created_at, revoked_at"


def create_api_user(user_id: str, name: str, role: str, token_hash: str, token_hint: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO api_users (user_id, name, role, token_hash, token_hint) "
            "VALUES (?, ?, ?, ?, ?)",
            (user_id, name, role, token_hash, token_hint),
        )


def get_api_user_by_token_hash(token_hash: str):
    """Usuário ATIVO (enabled=1) cujo token_hash bate. Devolve (user_id, name,
    role) ou None. Não retorna o hash."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT user_id, name, role FROM api_users WHERE token_hash = ? AND enabled = 1",
            (token_hash,),
        ).fetchone()


def list_api_users():
    """Metadados de todos os usuários (NUNCA o token nem o hash)."""
    with get_conn() as conn:
        return conn.execute(
            f"SELECT {_API_USER_COLS} FROM api_users ORDER BY created_at"
        ).fetchall()


def revoke_api_user(user_id: str) -> bool:
    """Desativa um usuário (enabled=0 + revoked_at). True se algo mudou."""
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE api_users SET enabled = 0, revoked_at = datetime('now') "
            "WHERE user_id = ? AND enabled = 1",
            (user_id,),
        )
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Casos / incidentes (Prioridade 6)
# ---------------------------------------------------------------------------

_INCIDENT_COLS = (
    "id, title, severity, status, owner, related_ip, related_asset, event_ids, "
    "timeline, evidence, actions_taken, created_at, updated_at, resolved_at"
)
_INCIDENT_UPDATABLE = {"title", "severity", "status", "owner", "related_ip", "related_asset"}
_INCIDENT_LIST_COLS = {"event_ids", "timeline", "evidence", "actions_taken"}


def create_incident(title: str, severity: str = "medium", owner: str = "",
                    related_ip: str = "", related_asset: str = "", status: str = "open") -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO incidents (title, severity, status, owner, related_ip, related_asset) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (title, severity, status, owner, related_ip, related_asset),
        )
        return cur.lastrowid


def get_incident(incident_id: int):
    with get_conn() as conn:
        return conn.execute(
            f"SELECT {_INCIDENT_COLS} FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()


def list_incidents(status: str | None = None, limit: int = 50):
    with get_conn() as conn:
        if status:
            return conn.execute(
                f"SELECT {_INCIDENT_COLS} FROM incidents WHERE status = ? ORDER BY id DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        return conn.execute(
            f"SELECT {_INCIDENT_COLS} FROM incidents ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()


def update_incident_fields(incident_id: int, **fields) -> bool:
    cols = {k: v for k, v in fields.items() if k in _INCIDENT_UPDATABLE}
    if not cols:
        return False
    sets = ", ".join(f"{c} = ?" for c in cols)
    resolved = ""
    if cols.get("status") in ("resolved", "false_positive"):
        resolved = ", resolved_at = datetime('now')"
    with get_conn() as conn:
        cur = conn.execute(
            f"UPDATE incidents SET {sets}, updated_at = datetime('now'){resolved} WHERE id = ?",
            (*cols.values(), incident_id),
        )
        return cur.rowcount > 0


def append_incident_list(incident_id: int, column: str, entry) -> bool:
    """Acrescenta um item a uma coluna-lista JSON do incidente (timeline/
    evidence/actions_taken/event_ids), atualizando updated_at."""
    if column not in _INCIDENT_LIST_COLS:
        raise ValueError(f"coluna de lista inválida: {column}")
    with get_conn() as conn:
        row = conn.execute(f"SELECT {column} FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if row is None:
            return False
        try:
            arr = json.loads(row[0]) if row[0] else []
        except (json.JSONDecodeError, TypeError):
            arr = []
        arr.append(entry)
        conn.execute(
            f"UPDATE incidents SET {column} = ?, updated_at = datetime('now') WHERE id = ?",
            (json.dumps(arr, ensure_ascii=False), incident_id),
        )
        return True


# ---------------------------------------------------------------------------
# Assinaturas HMAC de eventos (Prioridade 7) — canal lateral
# ---------------------------------------------------------------------------

def get_unsigned_events():
    """(id, entry_hash) de eventos com hash e SEM assinatura ainda."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT e.id, e.entry_hash FROM events e "
            "LEFT JOIN event_signatures s ON e.id = s.event_id "
            "WHERE e.entry_hash IS NOT NULL AND s.event_id IS NULL ORDER BY e.id"
        ).fetchall()


def add_event_signature(event_id: int, signature: str, algo: str = "hmac-sha256") -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO event_signatures (event_id, signature, algo) VALUES (?, ?, ?)",
            (event_id, signature, algo),
        )


def get_signed_events():
    """(id, entry_hash, signature) dos eventos assinados, para verificação."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT e.id, e.entry_hash, s.signature FROM events e "
            "JOIN event_signatures s ON e.id = s.event_id ORDER BY e.id"
        ).fetchall()


def get_event_signature(event_id: int):
    with get_conn() as conn:
        return conn.execute(
            "SELECT signature, algo, signed_at FROM event_signatures WHERE event_id = ?",
            (event_id,),
        ).fetchone()
