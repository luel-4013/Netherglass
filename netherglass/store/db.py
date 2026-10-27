"""SQLite storage layer. WAL mode, row factory, single-file durability.

The database is one file under the data directory with 0700 directory
permissions; it holds metadata, flows, findings, audit events and evidence
references. Raw PCAP lives as ring files under captures/ and encrypted
evidence blobs under evidence/.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'auditor')),
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    details TEXT NOT NULL DEFAULT '{}',
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS system_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS captures (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    interface TEXT,
    profile TEXT,
    status TEXT NOT NULL DEFAULT 'created',
    pcap_path TEXT,
    notes TEXT
);
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id TEXT NOT NULL,
    num INTEGER,
    ts REAL,
    src TEXT,
    dst TEXT,
    sport INTEGER,
    dport INTEGER,
    proto TEXT,
    length INTEGER,
    info TEXT,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_packets_capture_ts ON packets(capture_id, ts);
CREATE INDEX IF NOT EXISTS idx_packets_capture_addr ON packets(capture_id, src, dst);
CREATE TABLE IF NOT EXISTS flows (
    capture_id TEXT NOT NULL,
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    proto TEXT NOT NULL,
    dport INTEGER NOT NULL DEFAULT 0,
    packets INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    first_ts REAL,
    last_ts REAL,
    PRIMARY KEY (capture_id, src, dst, proto, dport)
);
CREATE TABLE IF NOT EXISTS hosts (
    capture_id TEXT NOT NULL,
    ip TEXT NOT NULL,
    mac TEXT,
    hostname TEXT,
    hostname_source TEXT,
    first_ts REAL,
    last_ts REAL,
    packets INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    sent_packets INTEGER NOT NULL DEFAULT 0,
    sent_bytes INTEGER NOT NULL DEFAULT 0,
    recv_packets INTEGER NOT NULL DEFAULT 0,
    recv_bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (capture_id, ip)
);
CREATE TABLE IF NOT EXISTS host_names (
    capture_id TEXT NOT NULL,
    ip TEXT NOT NULL,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    first_ts REAL,
    last_ts REAL,
    PRIMARY KEY (capture_id, ip, name, source)
);
CREATE TABLE IF NOT EXISTS services (
    capture_id TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    proto TEXT NOT NULL,
    app_proto TEXT,
    packets INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    first_ts REAL,
    last_ts REAL,
    PRIMARY KEY (capture_id, ip, port, proto)
);
CREATE TABLE IF NOT EXISTS dns_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id TEXT NOT NULL,
    ts REAL,
    client TEXT,
    server TEXT,
    qname TEXT NOT NULL,
    qtype TEXT,
    rcode TEXT,
    answers TEXT,
    cname_chain TEXT,
    ttl_min INTEGER,
    matched INTEGER NOT NULL DEFAULT 0,
    response_ts REAL,
    response_num INTEGER
);
CREATE INDEX IF NOT EXISTS idx_dns_events_capture_ts ON dns_events(capture_id, ts);
CREATE INDEX IF NOT EXISTS idx_dns_events_qname ON dns_events(capture_id, qname);
CREATE TABLE IF NOT EXISTS http_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id TEXT NOT NULL,
    ts REAL,
    src TEXT,
    dst TEXT,
    sport INTEGER,
    dport INTEGER,
    stream TEXT,
    kind TEXT NOT NULL DEFAULT 'request',
    method TEXT,
    host TEXT,
    path TEXT,
    query_names TEXT,
    status INTEGER,
    user_agent TEXT,
    content_type TEXT,
    server TEXT,
    version TEXT,
    auth_scheme TEXT,
    set_cookie_count INTEGER NOT NULL DEFAULT 0,
    cookie_count INTEGER NOT NULL DEFAULT 0,
    length INTEGER
);
CREATE INDEX IF NOT EXISTS idx_http_events_capture_ts ON http_events(capture_id, ts);
CREATE INDEX IF NOT EXISTS idx_http_events_host ON http_events(capture_id, host);
CREATE TABLE IF NOT EXISTS tls_sessions (
    capture_id TEXT NOT NULL,
    stream TEXT NOT NULL,
    client TEXT,
    server TEXT,
    sport INTEGER,
    dport INTEGER,
    version TEXT,
    sni TEXT,
    alpn TEXT,
    cipher TEXT,
    ja3 TEXT,
    ja4 TEXT,
    cert_count INTEGER,
    cert_sans TEXT,
    cert_name_strings TEXT,
    cert_not_before TEXT,
    cert_not_after TEXT,
    first_ts REAL,
    last_ts REAL,
    PRIMARY KEY (capture_id, stream)
);
CREATE INDEX IF NOT EXISTS idx_tls_sessions_sni ON tls_sessions(capture_id, sni);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    capture_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_version INTEGER NOT NULL DEFAULT 1,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    explanation TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    confidence TEXT NOT NULL CHECK (confidence IN ('OBSERVED', 'LIKELY', 'POSSIBLE', 'NOT_DETERMINED')),
    status TEXT NOT NULL DEFAULT 'OPEN',
    asset TEXT,
    src TEXT,
    dst TEXT,
    protocol TEXT,
    first_ts REAL,
    last_ts REAL,
    evidence_ids TEXT,
    packet_refs TEXT,
    related TEXT,
    case_id TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_capture ON findings(capture_id, severity);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    capture_id TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    field TEXT,
    src TEXT,
    sport INTEGER,
    dst TEXT,
    dport INTEGER,
    domain TEXT,
    host TEXT,
    protocol TEXT,
    app_proto TEXT,
    http_method TEXT,
    path TEXT,
    ts REAL,
    stream TEXT,
    frame INTEGER,
    confidence TEXT NOT NULL DEFAULT 'OBSERVED',
    transport_security TEXT,
    meta TEXT,
    sha256 TEXT,
    size INTEGER,
    status TEXT NOT NULL DEFAULT 'SEALED',
    case_id TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_capture ON evidence(capture_id, artifact_type);
CREATE TABLE IF NOT EXISTS web_cookies (
    capture_id TEXT NOT NULL,
    name TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT 'OTHER',
    set_observed INTEGER NOT NULL DEFAULT 0,
    secure INTEGER NOT NULL DEFAULT 0,
    http_only INTEGER NOT NULL DEFAULT 0,
    same_site TEXT,
    domain TEXT,
    path TEXT,
    max_age INTEGER,
    plaintext INTEGER NOT NULL DEFAULT 0,
    seen_count INTEGER NOT NULL DEFAULT 0,
    first_ts REAL,
    last_ts REAL,
    PRIMARY KEY (capture_id, name, host)
);
CREATE INDEX IF NOT EXISTS idx_web_cookies_capture ON web_cookies(capture_id);
CREATE TABLE IF NOT EXISTS web_headers (
    capture_id TEXT NOT NULL,
    host TEXT NOT NULL,
    responses INTEGER NOT NULL DEFAULT 0,
    hsts INTEGER NOT NULL DEFAULT 0,
    csp INTEGER NOT NULL DEFAULT 0,
    x_content_type_options INTEGER NOT NULL DEFAULT 0,
    x_frame_options INTEGER NOT NULL DEFAULT 0,
    referrer_policy INTEGER NOT NULL DEFAULT 0,
    permissions_policy INTEGER NOT NULL DEFAULT 0,
    cache_control TEXT,
    server TEXT,
    first_ts REAL,
    last_ts REAL,
    PRIMARY KEY (capture_id, host)
);
CREATE INDEX IF NOT EXISTS idx_web_headers_capture ON web_headers(capture_id);
CREATE TABLE IF NOT EXISTS web_tokens (
    capture_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT,
    alg TEXT,
    claims TEXT,
    hosts TEXT,
    clients TEXT,
    plaintext INTEGER NOT NULL DEFAULT 0,
    seen_count INTEGER NOT NULL DEFAULT 0,
    first_ts REAL,
    last_ts REAL,
    PRIMARY KEY (capture_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_web_tokens_capture ON web_tokens(capture_id);
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'CLOSED')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    closed_at TEXT
);
CREATE TABLE IF NOT EXISTS case_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    item_type TEXT NOT NULL,
    item_id TEXT NOT NULL,
    capture_id TEXT,
    note TEXT,
    added_by TEXT NOT NULL,
    added_at TEXT NOT NULL,
    UNIQUE (case_id, item_type, item_id)
);
CREATE INDEX IF NOT EXISTS idx_case_items_case ON case_items(case_id);
CREATE TABLE IF NOT EXISTS tunnels (
    capture_id TEXT NOT NULL,
    tunnel_proto TEXT NOT NULL,
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    sport INTEGER NOT NULL DEFAULT 0,
    dport INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'OBSERVED',
    inner_visible INTEGER NOT NULL DEFAULT 0,
    packets INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    first_ts REAL,
    last_ts REAL,
    PRIMARY KEY (capture_id, tunnel_proto, src, dst, sport, dport)
);
CREATE INDEX IF NOT EXISTS idx_tunnels_capture ON tunnels(capture_id);
CREATE TABLE IF NOT EXISTS k8s_entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('node', 'pod', 'service', 'namespace')),
    namespace TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    node TEXT,
    ip TEXT,
    labels TEXT,
    ports TEXT,
    first_ts REAL,
    last_ts REAL,
    UNIQUE (kind, namespace, name)
);
CREATE INDEX IF NOT EXISTS idx_k8s_entities_ip ON k8s_entities(ip);
CREATE TABLE IF NOT EXISTS controlled_tests (
    id TEXT PRIMARY KEY,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    authorization_ref TEXT NOT NULL,
    assessment_id TEXT,
    target TEXT NOT NULL,
    domain TEXT,
    port INTEGER,
    protocol TEXT,
    test_type TEXT NOT NULL,
    artifact_type TEXT,
    artifact_id TEXT,
    case_id TEXT,
    status TEXT NOT NULL DEFAULT 'PLANNED',
    dry_run INTEGER NOT NULL DEFAULT 1,
    rate_limit_ms INTEGER NOT NULL DEFAULT 1000,
    max_requests INTEGER NOT NULL DEFAULT 5,
    timeout_ms INTEGER NOT NULL DEFAULT 5000,
    window_start TEXT,
    window_end TEXT,
    request_count INTEGER NOT NULL DEFAULT 0,
    started_at TEXT,
    ended_at TEXT,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_controlled_tests_status
    ON controlled_tests(status, created_at);
CREATE TABLE IF NOT EXISTS controlled_test_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id TEXT NOT NULL REFERENCES controlled_tests(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL DEFAULT 0,
    ts TEXT NOT NULL,
    request_kind TEXT NOT NULL,
    method TEXT,
    url TEXT,
    status_code INTEGER,
    outcome TEXT NOT NULL,
    detail TEXT,
    duration_ms INTEGER,
    dry_run INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_controlled_test_results_test
    ON controlled_test_results(test_id, seq);
"""

CAPTURE_EXTRA_COLUMNS = {
    "source": "TEXT NOT NULL DEFAULT 'live'",
    "bpf": "TEXT",
    "started_at": "TEXT",
    "stopped_at": "TEXT",
    "packets_captured": "INTEGER NOT NULL DEFAULT 0",
    "packets_dropped": "INTEGER NOT NULL DEFAULT 0",
    "decode_drops": "INTEGER NOT NULL DEFAULT 0",
    "bytes_written": "INTEGER NOT NULL DEFAULT 0",
    "sha256": "TEXT",
    "original_filename": "TEXT",
    "error": "TEXT",
}

PACKET_EXTRA_COLUMNS = {
    "src_mac": "TEXT",
    "dst_mac": "TEXT",
    "app_proto": "TEXT",
    "encryption": "TEXT",
    "stream": "TEXT",
    "dns_qname": "TEXT",
    "dns_qtype": "TEXT",
    "dns_rcode": "TEXT",
    "tls_sni": "TEXT",
    "tls_version": "TEXT",
    "http_host": "TEXT",
    "http_method": "TEXT",
    "http_status": "INTEGER",
    "security": "TEXT",
}

TLS_EXTRA_COLUMNS = {
    "security": "TEXT",
}


class Database:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def migrate(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            capture_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(captures)")
            }
            for column, ddl in CAPTURE_EXTRA_COLUMNS.items():
                if column not in capture_columns:
                    conn.execute(f"ALTER TABLE captures ADD COLUMN {column} {ddl}")
            packet_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(packets)")
            }
            for column, ddl in PACKET_EXTRA_COLUMNS.items():
                if column not in packet_columns:
                    conn.execute(f"ALTER TABLE packets ADD COLUMN {column} {ddl}")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_packets_dns ON packets(capture_id, dns_qname)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_packets_tls ON packets(capture_id, tls_sni)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_packets_http ON packets(capture_id, http_host)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_packets_security ON packets(capture_id, security)"
            )
            tls_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(tls_sessions)")
            }
            for column, ddl in TLS_EXTRA_COLUMNS.items():
                if column not in tls_columns:
                    conn.execute(f"ALTER TABLE tls_sessions ADD COLUMN {column} {ddl}")
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', '7')"
            )
