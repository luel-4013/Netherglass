"""Data access for capture sessions, decoded packets and flow rollups."""

from __future__ import annotations

import sqlite3
from typing import Any, Iterable

CAPTURE_FIELDS = (
    "id, created_at, interface, profile, status, pcap_path, notes, source, bpf, "
    "started_at, stopped_at, packets_captured, packets_dropped, decode_drops, "
    "bytes_written, sha256, original_filename, error"
)


def create_capture(
    conn: sqlite3.Connection,
    *,
    capture_id: str,
    created_at: str,
    interface: str | None,
    profile: str,
    source: str,
    bpf: str | None,
    original_filename: str | None = None,
) -> None:
    conn.execute(
        "INSERT INTO captures(id, created_at, interface, profile, status, source, "
        "bpf, original_filename) VALUES (?, ?, ?, ?, 'created', ?, ?, ?)",
        (capture_id, created_at, interface, profile, source, bpf, original_filename),
    )


def update_capture(conn: sqlite3.Connection, capture_id: str, **fields: Any) -> None:
    allowed = set(CAPTURE_EXTRA_COLUMNS_KEYS)
    keys = [k for k in fields if k in allowed]
    if not keys:
        return
    assignments = ", ".join(f"{k} = ?" for k in keys)
    conn.execute(
        f"UPDATE captures SET {assignments} WHERE id = ?",
        [fields[k] for k in keys] + [capture_id],
    )


CAPTURE_EXTRA_COLUMNS_KEYS = (
    "status",
    "pcap_path",
    "notes",
    "interface",
    "profile",
    "source",
    "bpf",
    "started_at",
    "stopped_at",
    "packets_captured",
    "packets_dropped",
    "decode_drops",
    "bytes_written",
    "sha256",
    "original_filename",
    "error",
)


def get_capture(conn: sqlite3.Connection, capture_id: str) -> dict | None:
    row = conn.execute(
        f"SELECT {CAPTURE_FIELDS} FROM captures WHERE id = ?", (capture_id,)
    ).fetchone()
    return dict(row) if row else None


def list_captures(conn: sqlite3.Connection, limit: int = 100) -> list[dict]:
    rows = conn.execute(
        f"SELECT {CAPTURE_FIELDS} FROM captures ORDER BY created_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


PACKET_FIELDS = (
    "id, capture_id, num, ts, src, dst, sport, dport, proto, length, info, "
    "src_mac, dst_mac, app_proto, encryption, security, stream, dns_qname, "
    "dns_qtype, dns_rcode, tls_sni, tls_version, http_host, http_method, "
    "http_status"
)


def insert_packets(conn: sqlite3.Connection, rows: Iterable[dict]) -> int:
    payload = [
        (
            r["capture_id"],
            r.get("num"),
            r.get("ts"),
            r.get("src"),
            r.get("dst"),
            r.get("sport"),
            r.get("dport"),
            r.get("proto"),
            r.get("length"),
            r.get("info"),
            r.get("detail"),
            r.get("src_mac"),
            r.get("dst_mac"),
            r.get("app_proto"),
            r.get("encryption"),
            r.get("security"),
            r.get("stream"),
            r.get("dns_qname"),
            r.get("dns_qtype"),
            r.get("dns_rcode"),
            r.get("tls_sni"),
            r.get("tls_version"),
            r.get("http_host"),
            r.get("http_method"),
            r.get("http_status"),
        )
        for r in rows
    ]
    conn.executemany(
        "INSERT INTO packets(capture_id, num, ts, src, dst, sport, dport, proto, "
        "length, info, detail, src_mac, dst_mac, app_proto, encryption, security, "
        "stream, dns_qname, dns_qtype, dns_rcode, tls_sni, tls_version, http_host, "
        "http_method, http_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
        "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        payload,
    )
    return len(payload)


def upsert_flows(conn: sqlite3.Connection, rows: Iterable[dict]) -> int:
    payload = [
        (
            r["capture_id"],
            r["src"],
            r["dst"],
            r["proto"],
            r.get("dport") or 0,
            r.get("packets") or 0,
            r.get("bytes") or 0,
            r.get("first_ts"),
            r.get("last_ts"),
        )
        for r in rows
    ]
    conn.executemany(
        "INSERT INTO flows(capture_id, src, dst, proto, dport, packets, bytes, "
        "first_ts, last_ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(capture_id, src, dst, proto, dport) DO UPDATE SET "
        "packets = packets + excluded.packets, "
        "bytes = bytes + excluded.bytes, "
        "first_ts = MIN(COALESCE(first_ts, excluded.first_ts), excluded.first_ts), "
        "last_ts = MAX(COALESCE(last_ts, excluded.last_ts), excluded.last_ts)",
        payload,
    )
    return len(payload)


def list_packets(
    conn: sqlite3.Connection,
    capture_id: str,
    *,
    limit: int = 200,
    offset: int = 0,
    proto: str | None = None,
    addr: str | None = None,
    port: int | None = None,
) -> dict:
    where = ["capture_id = ?"]
    params: list[Any] = [capture_id]
    if proto:
        where.append("proto = ?")
        params.append(proto.lower())
    if addr:
        where.append("(src = ? OR dst = ?)")
        params.extend([addr, addr])
    if port:
        where.append("(sport = ? OR dport = ?)")
        params.extend([port, port])
    clause = " AND ".join(where)
    total = conn.execute(
        f"SELECT COUNT(*) AS n FROM packets WHERE {clause}", params
    ).fetchone()["n"]
    rows = conn.execute(
        f"SELECT {PACKET_FIELDS} FROM packets WHERE {clause} "
        "ORDER BY id LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()
    return {"total": total, "limit": limit, "offset": offset,
            "packets": [dict(row) for row in rows]}


def list_flows(
    conn: sqlite3.Connection, capture_id: str, *, limit: int = 200
) -> list[dict]:
    rows = conn.execute(
        "SELECT capture_id, src, dst, proto, dport, packets, bytes, first_ts, "
        "last_ts FROM flows WHERE capture_id = ? ORDER BY bytes DESC LIMIT ?",
        (capture_id, limit),
    ).fetchall()
    return [dict(row) for row in rows]


def capture_totals(conn: sqlite3.Connection, capture_id: str) -> dict:
    packet_row = conn.execute(
        "SELECT COUNT(*) AS packets, COALESCE(SUM(length), 0) AS bytes "
        "FROM packets WHERE capture_id = ?",
        (capture_id,),
    ).fetchone()
    flow_row = conn.execute(
        "SELECT COUNT(*) AS flows FROM flows WHERE capture_id = ?", (capture_id,)
    ).fetchone()
    host_row = conn.execute(
        "SELECT COUNT(*) AS hosts FROM hosts WHERE capture_id = ?", (capture_id,)
    ).fetchone()
    return {
        "decoded_packets": packet_row["packets"],
        "decoded_bytes": packet_row["bytes"],
        "flows": flow_row["flows"],
        "hosts": host_row["hosts"],
    }


def search_packets(
    conn: sqlite3.Connection,
    capture_id: str,
    where_sql: str,
    params: list[Any],
    *,
    limit: int = 200,
    offset: int = 0,
) -> dict:
    clause = f"capture_id = ? AND ({where_sql})"
    all_params = [capture_id] + list(params)
    total = conn.execute(
        f"SELECT COUNT(*) AS n FROM packets WHERE {clause}", all_params
    ).fetchone()["n"]
    rows = conn.execute(
        f"SELECT {PACKET_FIELDS} FROM packets WHERE {clause} "
        "ORDER BY ts IS NULL, ts, id LIMIT ? OFFSET ?",
        all_params + [limit, offset],
    ).fetchall()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "packets": [dict(row) for row in rows],
    }
