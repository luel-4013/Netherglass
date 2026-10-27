"""Investigation cases (spec section 39).

A case groups findings, evidence, hosts, domains and notes for one
investigation. Case IDs are monotonic (CS-000001). Items are linked by
(type, id) so the same finding or evidence record can only be added once.
"""

from __future__ import annotations

import sqlite3

from ..security.audit import utcnow_iso
from . import counters

CASE_STATUSES = ("OPEN", "CLOSED")
ITEM_TYPES = ("finding", "evidence", "host", "domain", "note", "capture")

_CASE_FIELDS = (
    "id, title, summary, status, created_by, created_at, closed_at"
)


class CaseError(ValueError):
    pass


def create_case(
    conn: sqlite3.Connection,
    *,
    title: str,
    summary: str,
    created_by: str,
) -> dict:
    title = title.strip()
    if len(title) < 3:
        raise CaseError("title must be at least 3 characters")
    case_id = counters.next_id(conn, "case", "CS")
    conn.execute(
        "INSERT INTO cases(id, title, summary, status, created_by, created_at) "
        "VALUES (?, ?, ?, 'OPEN', ?, ?)",
        (case_id, title[:200], summary.strip()[:4000], created_by, utcnow_iso()),
    )
    return get_case(conn, case_id) or {}


def get_case(conn: sqlite3.Connection, case_id: str) -> dict | None:
    row = conn.execute(
        f"SELECT {_CASE_FIELDS} FROM cases WHERE id = ?", (case_id,)
    ).fetchone()
    if row is None:
        return None
    case = dict(row)
    case["items"] = list_items(conn, case_id)
    return case


def list_cases(conn: sqlite3.Connection, *, limit: int = 100) -> list[dict]:
    rows = conn.execute(
        f"SELECT {_CASE_FIELDS} FROM cases ORDER BY created_at DESC, id DESC "
        "LIMIT ?",
        (limit,),
    ).fetchall()
    cases = []
    for row in rows:
        case = dict(row)
        case["item_count"] = conn.execute(
            "SELECT COUNT(*) AS n FROM case_items WHERE case_id = ?", (case["id"],)
        ).fetchone()["n"]
        cases.append(case)
    return cases


def update_case(
    conn: sqlite3.Connection,
    case_id: str,
    *,
    title: str | None = None,
    summary: str | None = None,
    status: str | None = None,
) -> dict:
    if get_case(conn, case_id) is None:
        raise CaseError("case not found")
    if status is not None:
        status = status.upper()
        if status not in CASE_STATUSES:
            raise CaseError(f"status must be one of {', '.join(CASE_STATUSES)}")
        conn.execute(
            "UPDATE cases SET status = ?, closed_at = ? WHERE id = ?",
            (status, utcnow_iso() if status == "CLOSED" else None, case_id),
        )
    if title is not None:
        title = title.strip()
        if len(title) < 3:
            raise CaseError("title must be at least 3 characters")
        conn.execute(
            "UPDATE cases SET title = ? WHERE id = ?", (title[:200], case_id)
        )
    if summary is not None:
        conn.execute(
            "UPDATE cases SET summary = ? WHERE id = ?",
            (summary.strip()[:4000], case_id),
        )
    return get_case(conn, case_id) or {}


def add_item(
    conn: sqlite3.Connection,
    case_id: str,
    *,
    item_type: str,
    item_id: str,
    capture_id: str | None,
    note: str | None,
    added_by: str,
) -> dict:
    if get_case(conn, case_id) is None:
        raise CaseError("case not found")
    item_type = item_type.lower()
    if item_type not in ITEM_TYPES:
        raise CaseError(f"item_type must be one of {', '.join(ITEM_TYPES)}")
    item_id = item_id.strip()
    if not item_id:
        raise CaseError("item_id is required")
    conn.execute(
        "INSERT OR IGNORE INTO case_items(case_id, item_type, item_id, capture_id, "
        "note, added_by, added_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            case_id,
            item_type,
            item_id[:128],
            capture_id,
            (note or "").strip()[:2000] or None,
            added_by,
            utcnow_iso(),
        ),
    )
    return get_case(conn, case_id) or {}


def remove_item(conn: sqlite3.Connection, case_id: str, item_id: int) -> dict:
    conn.execute(
        "DELETE FROM case_items WHERE case_id = ? AND id = ?", (case_id, item_id)
    )
    return get_case(conn, case_id) or {}


def list_items(conn: sqlite3.Connection, case_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT id, item_type, item_id, capture_id, note, added_by, added_at "
        "FROM case_items WHERE case_id = ? ORDER BY id",
        (case_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def cases_for_item(
    conn: sqlite3.Connection, item_type: str, item_id: str
) -> list[str]:
    rows = conn.execute(
        "SELECT DISTINCT case_id FROM case_items WHERE item_type = ? AND item_id = ?",
        (item_type, item_id),
    ).fetchall()
    return [row["case_id"] for row in rows]


def case_timeline(
    conn: sqlite3.Connection, case_id: str
) -> list[dict]:
    """Case-scoped timeline: linked findings, evidence and notes."""
    events: list[dict] = []
    for row in conn.execute(
        "SELECT i.id AS item_id, i.note, i.added_at, i.added_by, f.id, f.title, "
        "f.severity, f.confidence, f.first_ts, f.asset, f.capture_id "
        "FROM case_items i JOIN findings f ON f.id = i.item_id "
        "WHERE i.case_id = ? AND i.item_type = 'finding'",
        (case_id,),
    ):
        events.append(
            {
                "kind": "finding",
                "ts": row["first_ts"],
                "title": f"{row['severity']} {row['title']}",
                "detail": row["note"] or "",
                "ref": row["id"],
                "capture_id": row["capture_id"],
                "asset": row["asset"],
                "added_at": row["added_at"],
            }
        )
    for row in conn.execute(
        "SELECT i.id AS item_id, i.note, i.added_at, e.id, e.artifact_type, "
        "e.field, e.ts, e.host, e.capture_id "
        "FROM case_items i JOIN evidence e ON e.id = i.item_id "
        "WHERE i.case_id = ? AND i.item_type = 'evidence'",
        (case_id,),
    ):
        events.append(
            {
                "kind": "evidence",
                "ts": row["ts"],
                "title": f"EVIDENCE {row['artifact_type']}",
                "detail": row["note"] or row["field"] or "",
                "ref": row["id"],
                "capture_id": row["capture_id"],
                "asset": row["host"],
                "added_at": row["added_at"],
            }
        )
    for row in conn.execute(
        "SELECT id, note, added_at, added_by FROM case_items "
        "WHERE case_id = ? AND item_type = 'note' ORDER BY id",
        (case_id,),
    ):
        events.append(
            {
                "kind": "note",
                "ts": None,
                "title": "NOTE",
                "detail": row["note"] or "",
                "ref": f"note-{row['id']}",
                "capture_id": None,
                "asset": None,
                "added_at": row["added_at"],
            }
        )
    return events
