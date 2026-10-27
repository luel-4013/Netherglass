"""Evidence store: encrypted-only sensitive artifacts (spec sections 18-24, 61).

Metadata rows are ordinary SQL; the observed value is sealed with AES-256-GCM
into <data_dir>/evidence/<EVD>.ngv with the evidence ID as associated data.
There is deliberately no code path that returns a value except `reveal`, and
callers of `reveal` must audit the access.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from ..config import CAPTURE_PROFILES
from . import counters
from .vault import open_evidence, seal_evidence


class EvidenceError(RuntimeError):
    def __init__(self, message: str, *, code: int = 409) -> None:
        super().__init__(message)
        self.code = code


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _meta_json(meta: dict | None) -> str | None:
    if not meta:
        return None
    return json.dumps(meta, sort_keys=True)


def seal_candidates(
    conn: sqlite3.Connection,
    capture_id: str,
    candidates: list[dict],
    *,
    profile: str,
    data_dir: Path,
) -> list[str]:
    capture_profile = CAPTURE_PROFILES.get(profile)
    store_values = bool(capture_profile and capture_profile.store_sensitive_values)
    keys_dir = Path(data_dir) / "keys"
    evidence_dir = Path(data_dir) / "evidence"
    created: list[str] = []
    for candidate in candidates:
        evidence_id = counters.next_id(conn, "evidence", "EVD")
        sha256: str | None = None
        size: int | None = None
        status = "METADATA_ONLY"
        value = candidate.get("value")
        if store_values and value:
            blob = json.dumps(
                {"value": value, "source": candidate.get("source")}
            ).encode("utf-8")
            info = seal_evidence(keys_dir, evidence_dir, evidence_id, blob)
            sha256 = info["sha256"]
            size = info["size"]
            status = "SEALED"
        conn.execute(
            """
            INSERT INTO evidence(id, capture_id, artifact_type, field, src, sport,
                                 dst, dport, domain, host, protocol, app_proto,
                                 http_method, path, ts, stream, frame, confidence,
                                 transport_security, meta, sha256, size, status,
                                 created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?)
            """,
            (
                evidence_id,
                capture_id,
                candidate["type"],
                candidate.get("field"),
                candidate.get("src"),
                candidate.get("sport"),
                candidate.get("dst"),
                candidate.get("dport"),
                candidate.get("domain"),
                candidate.get("host"),
                candidate.get("protocol"),
                candidate.get("app_proto"),
                candidate.get("http_method"),
                candidate.get("path"),
                candidate.get("ts"),
                candidate.get("stream"),
                candidate.get("frame"),
                candidate.get("confidence") or "OBSERVED",
                candidate.get("transport_security"),
                _meta_json(candidate.get("meta")),
                sha256,
                size,
                status,
                _utcnow(),
            ),
        )
        created.append(evidence_id)
    return created


_EVIDENCE_FIELDS = (
    "id, capture_id, artifact_type, field, src, sport, dst, dport, domain, host, "
    "protocol, app_proto, http_method, path, ts, stream, frame, confidence, "
    "transport_security, meta, sha256, size, status, case_id, created_at"
)


def list_evidence(
    conn: sqlite3.Connection,
    capture_id: str,
    *,
    artifact_type: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> dict:
    where = ["capture_id = ?"]
    params: list = [capture_id]
    if artifact_type:
        where.append("artifact_type = ?")
        params.append(artifact_type.upper())
    clause = " AND ".join(where)
    total = conn.execute(
        f"SELECT COUNT(*) AS n FROM evidence WHERE {clause}", params
    ).fetchone()["n"]
    rows = conn.execute(
        f"SELECT {_EVIDENCE_FIELDS} FROM evidence WHERE {clause} "
        "ORDER BY ts IS NULL, ts, id LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "artifacts": [dict(row) for row in rows],
    }


def get_evidence(conn: sqlite3.Connection, evidence_id: str) -> dict | None:
    row = conn.execute(
        f"SELECT {_EVIDENCE_FIELDS} FROM evidence WHERE id = ?", (evidence_id,)
    ).fetchone()
    return dict(row) if row else None


def reveal_value(data_dir: Path, row: dict) -> dict:
    if row.get("status") != "SEALED":
        raise EvidenceError(
            "value not retained: this artifact was captured under a "
            "metadata-only profile",
            code=409,
        )
    keys_dir = Path(data_dir) / "keys"
    evidence_dir = Path(data_dir) / "evidence"
    try:
        blob = open_evidence(keys_dir, evidence_dir, row["id"])
    except (OSError, ValueError) as exc:
        raise EvidenceError(f"evidence blob unreadable: {exc}", code=410) from exc
    try:
        payload = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("evidence blob is not valid JSON", code=500) from exc
    return {"value": payload.get("value"), "source": payload.get("source")}


def delete_evidence(
    data_dir: Path, conn: sqlite3.Connection, evidence_id: str, *, reason: str
) -> dict:
    row = get_evidence(conn, evidence_id)
    if row is None:
        raise EvidenceError(f"evidence not found: {evidence_id}", code=404)
    if row["status"] == "DELETED":
        raise EvidenceError(f"evidence already deleted: {evidence_id}", code=409)
    removed = False
    if row["status"] == "SEALED":
        blob_path = Path(data_dir) / "evidence" / f"{evidence_id}.ngv"
        if blob_path.is_file():
            size = blob_path.stat().st_size
            with open(blob_path, "r+b") as handle:
                handle.write(b"\x00" * size)
                handle.flush()
                os.fsync(handle.fileno())
            blob_path.unlink()
            removed = True
        else:
            removed = True
    conn.execute(
        "UPDATE evidence SET status = 'DELETED', meta = ? WHERE id = ?",
        (
            _meta_json({"deleted_reason": reason[:256], "blob_removed": removed}),
            evidence_id,
        ),
    )
    updated = get_evidence(conn, evidence_id)
    assert updated is not None
    return updated


def summary(conn: sqlite3.Connection, capture_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT artifact_type, COUNT(*) AS count, "
        "SUM(CASE WHEN status = 'SEALED' THEN 1 ELSE 0 END) AS sealed, "
        "SUM(CASE WHEN status = 'METADATA_ONLY' THEN 1 ELSE 0 END) AS metadata_only "
        "FROM evidence WHERE capture_id = ? GROUP BY artifact_type "
        "ORDER BY count DESC",
        (capture_id,),
    ).fetchall()
    return [dict(row) for row in rows]
