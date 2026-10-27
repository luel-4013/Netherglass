"""Monotonic ID counters persisted in the meta table (FND-000001, EVD-000001)."""

from __future__ import annotations

import sqlite3

COUNTER_KEYS = {
    "finding": "next_finding_id",
    "evidence": "next_evidence_id",
    "case": "next_case_id",
    "controlled_test": "next_controlled_test_id",
}


def next_id(conn: sqlite3.Connection, kind: str, prefix: str) -> str:
    key = COUNTER_KEYS[kind]
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    current = int(row["value"]) if row else 1
    conn.execute(
        "INSERT INTO meta(key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, str(current + 1)),
    )
    return f"{prefix}-{current:06d}"
