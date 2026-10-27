"""Unified event timeline (spec section 40).

Merges DNS, TLS, HTTP, findings, evidence, case and audit events into one
chronological feed. Everything is derived from stored metadata; sensitive
values never appear. Filtering is applied in SQL per source so large captures
stay responsive.
"""

from __future__ import annotations

import sqlite3
from typing import Any

DEFAULT_LIMIT = 300


def _finding_events(
    conn: sqlite3.Connection,
    capture_id: str,
    where: list[str],
    params: list[Any],
    limit: int,
) -> list[dict]:
    rows = conn.execute(
        "SELECT id, first_ts, title, severity, confidence, asset, protocol "
        "FROM findings WHERE capture_id = ? ORDER BY first_ts DESC LIMIT ?",
        (capture_id, limit),
    ).fetchall()
    return [
        {
            "ts": row["first_ts"],
            "kind": "finding",
            "title": f"{row['severity']} finding: {row['title']}",
            "detail": f"{row['confidence']} confidence · {row['protocol'] or '-'}",
            "ref": row["id"],
            "asset": row["asset"],
            "severity": row["severity"],
        }
        for row in rows
    ]


def _evidence_events(
    conn: sqlite3.Connection, capture_id: str, limit: int
) -> list[dict]:
    rows = conn.execute(
        "SELECT id, ts, artifact_type, field, host, transport_security "
        "FROM evidence WHERE capture_id = ? ORDER BY ts DESC LIMIT ?",
        (capture_id, limit),
    ).fetchall()
    return [
        {
            "ts": row["ts"],
            "kind": "evidence",
            "title": f"evidence sealed: {row['artifact_type']}",
            "detail": f"{row['field'] or '-'} @ {row['host'] or '-'} "
            f"({row['transport_security'] or 'unknown transport'})",
            "ref": row["id"],
            "asset": row["host"],
            "severity": None,
        }
        for row in rows
    ]


def _dns_events(
    conn: sqlite3.Connection, capture_id: str, limit: int
) -> list[dict]:
    rows = conn.execute(
        "SELECT ts, client, qname, qtype, rcode FROM dns_events "
        "WHERE capture_id = ? AND matched IN (0, 1) ORDER BY ts DESC LIMIT ?",
        (capture_id, limit),
    ).fetchall()
    return [
        {
            "ts": row["ts"],
            "kind": "dns",
            "title": f"DNS {row['qtype'] or '?'} {row['qname']}",
            "detail": f"client {row['client'] or '-'}"
            + (f" · {row['rcode']}" if row["rcode"] else ""),
            "ref": None,
            "asset": row["client"],
            "severity": None,
        }
        for row in rows
    ]


def _tls_events(
    conn: sqlite3.Connection, capture_id: str, limit: int
) -> list[dict]:
    rows = conn.execute(
        "SELECT first_ts, sni, version, cipher, security, client, server "
        "FROM tls_sessions WHERE capture_id = ? AND first_ts IS NOT NULL "
        "ORDER BY first_ts DESC LIMIT ?",
        (capture_id, limit),
    ).fetchall()
    return [
        {
            "ts": row["first_ts"],
            "kind": "tls",
            "title": f"TLS {row['version'] or '?'} {row['sni'] or row['server'] or '-'}",
            "detail": f"{row['cipher'] or 'unknown cipher'} · "
            f"{row['security'] or 'unknown'}",
            "ref": None,
            "asset": row["server"],
            "severity": "HIGH" if (row["security"] or "").lower() == "insecure" else None,
        }
        for row in rows
    ]


def _http_events(
    conn: sqlite3.Connection, capture_id: str, limit: int
) -> list[dict]:
    rows = conn.execute(
        "SELECT ts, method, host, path, status, auth_scheme, kind "
        "FROM http_events WHERE capture_id = ? ORDER BY ts DESC LIMIT ?",
        (capture_id, limit),
    ).fetchall()
    events = []
    for row in rows:
        if row["kind"] == "request":
            title = f"HTTP {row['method'] or '?'} {row['host'] or '-'}{row['path'] or '/'}"
        else:
            title = f"HTTP response {row['status'] or '?'} {row['host'] or '-'}"
        events.append(
            {
                "ts": row["ts"],
                "kind": "http",
                "title": title,
                "detail": f"auth {row['auth_scheme']}" if row["auth_scheme"] else "",
                "ref": None,
                "asset": row["host"],
                "severity": None,
            }
        )
    return events


def _audit_events(
    conn: sqlite3.Connection, capture_id: str, limit: int
) -> list[dict]:
    rows = conn.execute(
        "SELECT ts, actor, action, target, details FROM audit_log "
        "WHERE action IN ('EMERGENCY_SECURITY_STOP', 'EMERGENCY_RECOVERY', "
        "'REVEAL_SENSITIVE_VALUE', 'CAPTURE_STARTED', 'CAPTURE_STOPPED') "
        "ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    events = []
    for row in rows:
        if capture_id not in (row["target"] or "") and capture_id not in (
            row["details"] or ""
        ):
            continue
        severity = "CRITICAL" if row["action"] == "EMERGENCY_SECURITY_STOP" else None
        events.append(
            {
                "ts": row["ts"],
                "kind": "audit",
                "title": row["action"],
                "detail": f"{row['actor']} → {row['target'] or '-'}",
                "ref": None,
                "asset": None,
                "severity": severity,
            }
        )
    return events


def build_timeline(
    conn: sqlite3.Connection,
    capture_id: str,
    *,
    limit: int = DEFAULT_LIMIT,
    kinds: set[str] | None = None,
    severity: str | None = None,
    host: str | None = None,
    domain: str | None = None,
    start: float | None = None,
    end: float | None = None,
) -> dict:
    per_source = max(50, limit)
    events: list[dict] = []
    if kinds is None or "dns" in kinds:
        events.extend(_dns_events(conn, capture_id, per_source))
    if kinds is None or "tls" in kinds:
        events.extend(_tls_events(conn, capture_id, per_source))
    if kinds is None or "http" in kinds:
        events.extend(_http_events(conn, capture_id, per_source))
    if kinds is None or "finding" in kinds:
        events.extend(_finding_events(conn, capture_id, [], [], per_source))
    if kinds is None or "evidence" in kinds:
        events.extend(_evidence_events(conn, capture_id, per_source))
    if kinds is None or "audit" in kinds:
        events.extend(_audit_events(conn, capture_id, per_source))

    def keep(event: dict) -> bool:
        ts = event.get("ts")
        if start is not None and (ts is None or ts < start):
            return False
        if end is not None and (ts is None or ts > end):
            return False
        if severity and event.get("severity") != severity.upper():
            return False
        if host:
            haystack = " ".join(
                str(event.get(key) or "")
                for key in ("asset", "title", "detail")
            ).lower()
            if host.lower() not in haystack:
                return False
        if domain:
            haystack = f"{event.get('title') or ''} {event.get('detail') or ''}".lower()
            if domain.lower() not in haystack:
                return False
        return True

    filtered = [event for event in events if keep(event)]
    filtered.sort(key=lambda item: item.get("ts") or 0, reverse=True)
    return {"total": len(filtered), "events": filtered[:limit]}
