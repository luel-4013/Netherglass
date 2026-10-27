"""Hash-chained audit log.

Every event carries the hash of the previous event, producing a tamper-evident
chain (the same approach proven in the Breadcrumb project). Event details are
scrubbed with the logging redaction patterns before storage, so passwords,
tokens and cookies never enter the audit record itself.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone

from ..logging_setup import redact


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _scrub(value):
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    if isinstance(value, str):
        return redact(value)
    return value


def append_event(
    conn: sqlite3.Connection,
    actor: str,
    action: str,
    target: str | None = None,
    details: dict | None = None,
    ts: str | None = None,
) -> dict:
    details = _scrub(details or {})
    ts = ts or utcnow_iso()
    previous = conn.execute(
        "SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    prev_hash = previous["hash"] if previous else "GENESIS"
    payload = {
        "ts": ts,
        "actor": actor,
        "action": action,
        "target": target,
        "details": details,
    }
    digest = hashlib.sha256((prev_hash + _canonical(payload)).encode("utf-8")).hexdigest()
    cursor = conn.execute(
        "INSERT INTO audit_log(ts, actor, action, target, details, prev_hash, hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ts, actor, action, target, _canonical(details), prev_hash, digest),
    )
    return {
        "id": cursor.lastrowid,
        "ts": ts,
        "actor": actor,
        "action": action,
        "target": target,
        "details": details,
        "hash": digest,
    }


def verify_chain(conn: sqlite3.Connection) -> tuple[bool, int]:
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
    prev_hash = "GENESIS"
    for index, row in enumerate(rows, start=1):
        payload = {
            "ts": row["ts"],
            "actor": row["actor"],
            "action": row["action"],
            "target": row["target"],
            "details": json.loads(row["details"]),
        }
        digest = hashlib.sha256(
            (prev_hash + _canonical(payload)).encode("utf-8")
        ).hexdigest()
        if row["prev_hash"] != prev_hash or row["hash"] != digest:
            return False, index
        prev_hash = row["hash"]
    return True, len(rows)


def list_events(conn: sqlite3.Connection, limit: int = 100) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [
        {
            "id": row["id"],
            "ts": row["ts"],
            "actor": row["actor"],
            "action": row["action"],
            "target": row["target"],
            "details": json.loads(row["details"]),
            "hash": row["hash"],
        }
        for row in rows
    ]
