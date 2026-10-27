"""Findings storage (spec sections 34-36, 57).

Findings are rebuilt atomically per capture when the rule engine runs; IDs are
stable only within one analysis run (rule_id + evidence references carry the
real identity). Every finding records severity AND confidence using the
mandated vocabulary; remediation text is mandatory for client-facing use.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from ..security.audit import utcnow_iso
from . import counters

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
CONFIDENCES = ("OBSERVED", "LIKELY", "POSSIBLE", "NOT_DETERMINED")

_FINDING_FIELDS = (
    "id, capture_id, rule_id, rule_version, title, description, explanation, "
    "remediation, severity, confidence, status, asset, src, dst, protocol, "
    "first_ts, last_ts, evidence_ids, packet_refs, related, case_id, created_at"
)


def _json_list(items: Any) -> str | None:
    if not items:
        return None
    return json.dumps(list(items)[:64])


def rebuild(
    conn: sqlite3.Connection, capture_id: str, payloads: list[dict]
) -> int:
    conn.execute("DELETE FROM findings WHERE capture_id = ?", (capture_id,))
    created = 0
    for payload in payloads:
        severity = str(payload.get("severity") or "").upper()
        if severity not in SEVERITIES:
            severity = "INFO"
        confidence = str(payload.get("confidence") or "").upper()
        if confidence not in CONFIDENCES:
            confidence = "NOT_DETERMINED"
        finding_id = counters.next_id(conn, "finding", "FND")
        conn.execute(
            """
            INSERT INTO findings(id, capture_id, rule_id, rule_version, title,
                                 description, explanation, remediation, severity,
                                 confidence, status, asset, src, dst, protocol,
                                 first_ts, last_ts, evidence_ids, packet_refs,
                                 related, case_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, NULL, ?)
            """,
            (
                finding_id,
                capture_id,
                payload.get("rule_id") or "unknown",
                int(payload.get("rule_version") or 1),
                payload.get("title") or "Finding",
                payload.get("description") or "",
                payload.get("explanation") or "",
                payload.get("remediation") or "",
                severity,
                confidence,
                payload.get("asset"),
                payload.get("src"),
                payload.get("dst"),
                payload.get("protocol"),
                payload.get("first_ts"),
                payload.get("last_ts"),
                _json_list(payload.get("evidence_ids")),
                _json_list(payload.get("packet_refs")),
                _json_list(payload.get("related")),
                utcnow_iso(),
            ),
        )
        created += 1
    return created


def list_findings(
    conn: sqlite3.Connection,
    capture_id: str,
    *,
    severity: str | None = None,
    confidence: str | None = None,
    status: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> dict:
    where = ["capture_id = ?"]
    params: list = [capture_id]
    if severity:
        where.append("severity = ?")
        params.append(severity.upper())
    if confidence:
        where.append("confidence = ?")
        params.append(confidence.upper())
    if status:
        where.append("status = ?")
        params.append(status.upper())
    clause = " AND ".join(where)
    total = conn.execute(
        f"SELECT COUNT(*) AS n FROM findings WHERE {clause}", params
    ).fetchone()["n"]
    rows = conn.execute(
        f"SELECT {_FINDING_FIELDS} FROM findings WHERE {clause} "
        "ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
        "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, first_ts, id "
        "LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "findings": [dict(row) for row in rows],
    }


def get_finding(conn: sqlite3.Connection, finding_id: str) -> dict | None:
    row = conn.execute(
        f"SELECT {_FINDING_FIELDS} FROM findings WHERE id = ?", (finding_id,)
    ).fetchone()
    return dict(row) if row else None


def summary(conn: sqlite3.Connection, capture_id: str) -> dict:
    by_severity = {
        row["severity"]: row["n"]
        for row in conn.execute(
            "SELECT severity, COUNT(*) AS n FROM findings WHERE capture_id = ? "
            "GROUP BY severity",
            (capture_id,),
        ).fetchall()
    }
    by_confidence = {
        row["confidence"]: row["n"]
        for row in conn.execute(
            "SELECT confidence, COUNT(*) AS n FROM findings WHERE capture_id = ? "
            "GROUP BY confidence",
            (capture_id,),
        ).fetchall()
    }
    total = sum(by_severity.values())
    return {
        "available": True,
        "total": total,
        "by_severity": by_severity,
        "by_confidence": by_confidence,
    }
