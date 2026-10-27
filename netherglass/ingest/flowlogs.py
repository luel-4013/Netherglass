"""Cloud flow-log adapters: AWS VPC, Azure NSG, GCP VPC, generic JSON/CSV.

Honesty rule (spec section 42): flow logs carry metadata only. Imports create
a capture with source ``cloud-flowlog``, no packet rows, and no journey into
the sensitive-data pipeline.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

from ..security.audit import append_event
from ..store import packets as packets_store
from ..store.db import Database

FLOWLOG_FORMATS = ("aws", "azure", "gcp", "generic-json", "generic-csv")

_PROTO_BY_NUMBER = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 58: "icmpv6"}
_MAX_ROWS = 200_000


class FlowlogError(ValueError):
    """Invalid flow-log input."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _capture_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"cap-{stamp}-{secrets.token_hex(2)}"


def _proto(value) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return "unknown"
    if text.isdigit():
        return _PROTO_BY_NUMBER.get(int(text), f"ip-{text}")
    return text


def _ip(value) -> str | None:
    text = str(value or "").strip()
    if not text or text in ("-", "NODATA", "SKIPDATA"):
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _int(value, default=0) -> int:
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def _float(value) -> float | None:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _epoch(value) -> float | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        value_int = int(text)
        if value_int > 10_000_000_000:
            value_int //= 1000
        return float(value_int)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def detect_format(path: Path) -> str:
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix in (".csv", ".tsv"):
        return "generic-csv"
    sample = path.read_text(errors="ignore")[:65536]
    stripped = sample.lstrip()
    if stripped.startswith(("{", "[")):
        lowered = stripped[:65536].lower()
        if '"records"' in lowered and "flowtuples" in lowered:
            return "azure"
        if '"connection"' in lowered or '"dest_ip"' in lowered:
            return "gcp"
        return "generic-json"
    if suffix in (".json", ".jsonl"):
        return "generic-json"
    lines = [line for line in sample.splitlines() if line.strip()]
    if lines and lines[0].startswith("version "):
        return "aws"
    first = lines[0].split() if lines else []
    if len(first) >= 10 and first[0].isdigit():
        return "aws"
    lowered = sample.lower()
    if "flowtuples" in lowered:
        return "azure"
    raise FlowlogError("could not detect flow-log format; pass format explicitly")


def _ts(value) -> float | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    numeric = _float(text)
    if numeric is not None:
        return numeric
    return _epoch(text)


def _normalize_row(row: dict) -> dict | None:
    src = _ip(row.get("src"))
    dst = _ip(row.get("dst"))
    if not src or not dst:
        return None
    packets = max(1, _int(row.get("packets"), 1))
    length = max(0, _int(row.get("bytes"), 0))
    first = _ts(row.get("first_ts")) or _ts(row.get("ts"))
    last = _ts(row.get("last_ts")) or first
    return {
        "src": src,
        "dst": dst,
        "sport": _int(row.get("sport"), 0),
        "dport": _int(row.get("dport"), 0),
        "proto": _proto(row.get("proto")),
        "packets": packets,
        "bytes": length,
        "first_ts": first,
        "last_ts": last,
        "action": str(row.get("action") or "").strip().upper() or None,
    }


def _parse_aws(text: str) -> list[dict]:
    rows: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("version ") or line.startswith("account-id"):
            continue
        parts = line.split()
        if len(parts) < 12 or not parts[0].isdigit():
            continue
        row = {
            "src": parts[3],
            "dst": parts[4],
            "sport": parts[5],
            "dport": parts[6],
            "proto": parts[7],
            "packets": parts[8],
            "bytes": parts[9],
            "first_ts": parts[10],
            "last_ts": parts[11],
            "action": parts[12] if len(parts) > 12 else None,
        }
        normalized = _normalize_row(row)
        if normalized is not None:
            rows.append(normalized)
        if len(rows) >= _MAX_ROWS:
            break
    return rows


def _parse_azure(text: str) -> list[dict]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FlowlogError(f"invalid azure NSG JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise FlowlogError("azure NSG JSON must be an object with 'records'")
    records = data.get("records", [])
    if not isinstance(records, list):
        raise FlowlogError("azure NSG 'records' must be a list")
    rows: list[dict] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        properties = record.get("properties", {})
        if not isinstance(properties, dict):
            continue
        rule_flows = properties.get("flows", [])
        if not isinstance(rule_flows, list):
            continue
        for rule_flow in rule_flows:
            if not isinstance(rule_flow, dict):
                continue
            flows = rule_flow.get("flows", [])
            if not isinstance(flows, list):
                continue
            for flow in flows:
                if not isinstance(flow, dict):
                    continue
                tuples = flow.get("flowTuples", [])
                if not isinstance(tuples, list):
                    continue
                for tuple_text in tuples:
                    if not isinstance(tuple_text, str):
                        continue
                    parts = [part.strip() for part in tuple_text.split(",")]
                    if len(parts) < 8:
                        continue
                    row = {
                        "ts": parts[0],
                        "src": parts[1],
                        "dst": parts[2],
                        "sport": parts[3],
                        "dport": parts[4],
                        "proto": {"t": "tcp", "u": "udp"}.get(
                            parts[5].lower(), parts[5]
                        ),
                        "action": parts[7],
                        "packets": 1,
                        "bytes": 0,
                    }
                    normalized = _normalize_row(row)
                    if normalized is not None:
                        rows.append(normalized)
        if len(rows) >= _MAX_ROWS:
            break
    return rows


def _parse_gcp(text: str) -> list[dict]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FlowlogError(f"invalid GCP flow JSON: {exc}") from exc
    if isinstance(data, dict):
        entries = data.get("entries") or data.get("logs") or [data]
    elif isinstance(data, list):
        entries = data
    else:
        raise FlowlogError("unsupported GCP flow JSON shape")
    rows: list[dict] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        payload = entry
        if isinstance(entry.get("jsonPayload"), dict):
            payload = entry["jsonPayload"]
        connection = payload.get("connection") or payload
        if not isinstance(connection, dict) or not connection.get("src_ip"):
            continue
        packet_total = (
            payload.get("packets_sent")
            or payload.get("packets")
            or connection.get("packets_sent")
            or connection.get("packets")
        )
        byte_total = (
            _int(payload.get("bytes_sent"), 0)
            + _int(payload.get("bytes_received"), 0)
            + _int(payload.get("bytes"), 0)
            + _int(connection.get("bytes_sent"), 0)
            + _int(connection.get("bytes_received"), 0)
        )
        row = {
            "src": connection.get("src_ip"),
            "dst": connection.get("dest_ip") or connection.get("dst_ip"),
            "sport": connection.get("src_port"),
            "dport": connection.get("dest_port") or connection.get("dst_port"),
            "proto": connection.get("protocol"),
            "packets": packet_total,
            "bytes": byte_total,
            "first_ts": payload.get("start_time") or payload.get("timestamp"),
            "last_ts": payload.get("end_time") or payload.get("timestamp"),
            "action": payload.get("reporter"),
        }
        normalized = _normalize_row(row)
        if normalized is not None:
            rows.append(normalized)
        if len(rows) >= _MAX_ROWS:
            break
    return rows


_JSON_KEYS = {
    "src": ("src", "srcaddr", "src_ip", "source", "source_ip", "srcip"),
    "dst": ("dst", "dstaddr", "dest_ip", "destination", "destination_ip", "dstip"),
    "sport": ("sport", "srcport", "src_port", "source_port"),
    "dport": ("dport", "dstport", "dest_port", "destination_port"),
    "proto": ("proto", "protocol"),
    "packets": ("packets", "packets_sent", "num_packets"),
    "bytes": ("bytes", "bytes_sent", "num_bytes"),
    "first_ts": ("ts", "timestamp", "start", "start_time", "first_ts", "time"),
    "last_ts": ("end", "end_time", "last_ts"),
    "action": ("action", "disposition", "status"),
}


def _pick(row: dict, field: str):
    for key in _JSON_KEYS[field]:
        if key in row:
            return row[key]
    return None


def _parse_generic_json(text: str) -> list[dict]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FlowlogError(f"invalid JSON: {exc}") from exc
    if isinstance(data, dict):
        entries = data.get("flows") or data.get("records") or data.get("entries")
        if entries is None:
            entries = [data]
    else:
        entries = data
    rows: list[dict] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        row = {field: _pick(entry, field) for field in _JSON_KEYS}
        normalized = _normalize_row(row)
        if normalized is not None:
            rows.append(normalized)
        if len(rows) >= _MAX_ROWS:
            break
    return rows


def _parse_generic_csv(text: str) -> list[dict]:
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        raise FlowlogError("CSV flow log has no header row")
    rows: list[dict] = []
    for record in reader:
        lowered = {
            key.strip().lower(): value for key, value in record.items() if key
        }
        row = {}
        for field, keys in _JSON_KEYS.items():
            for key in keys:
                if key in lowered:
                    row[field] = lowered[key]
                    break
        normalized = _normalize_row(row)
        if normalized is not None:
            rows.append(normalized)
        if len(rows) >= _MAX_ROWS:
            break
    return rows


def parse_flowlogs(text: str, fmt: str) -> list[dict]:
    fmt = fmt.lower()
    if fmt == "aws":
        return _parse_aws(text)
    if fmt == "azure":
        return _parse_azure(text)
    if fmt == "gcp":
        return _parse_gcp(text)
    if fmt == "generic-json":
        return _parse_generic_json(text)
    if fmt == "generic-csv":
        return _parse_generic_csv(text)
    raise FlowlogError(f"unsupported flow-log format: {fmt}")


def _bulk_host(
    conn,
    capture_id: str,
    ip: str,
    *,
    sent_packets: int = 0,
    sent_bytes: int = 0,
    recv_packets: int = 0,
    recv_bytes: int = 0,
    first_ts: float | None = None,
    last_ts: float | None = None,
) -> None:
    packets = sent_packets + recv_packets
    length = sent_bytes + recv_bytes
    conn.execute(
        """
        INSERT INTO hosts(capture_id, ip, first_ts, last_ts, packets, bytes,
                          sent_packets, sent_bytes, recv_packets, recv_bytes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(capture_id, ip) DO UPDATE SET
            packets = hosts.packets + excluded.packets,
            bytes = hosts.bytes + excluded.bytes,
            sent_packets = hosts.sent_packets + excluded.sent_packets,
            sent_bytes = hosts.sent_bytes + excluded.sent_bytes,
            recv_packets = hosts.recv_packets + excluded.recv_packets,
            recv_bytes = hosts.recv_bytes + excluded.recv_bytes,
            first_ts = MIN(COALESCE(hosts.first_ts, excluded.first_ts),
                           excluded.first_ts),
            last_ts = MAX(COALESCE(hosts.last_ts, excluded.last_ts),
                          excluded.last_ts)
        """,
        (
            capture_id,
            ip,
            first_ts,
            last_ts,
            packets,
            length,
            sent_packets,
            sent_bytes,
            recv_packets,
            recv_bytes,
        ),
    )


def _bulk_service(
    conn,
    capture_id: str,
    ip: str,
    port: int,
    proto: str,
    packets: int,
    length: int,
    first_ts: float | None,
    last_ts: float | None,
) -> None:
    if not port:
        return
    conn.execute(
        """
        INSERT INTO services(capture_id, ip, port, proto, packets, bytes, first_ts,
                             last_ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(capture_id, ip, port, proto) DO UPDATE SET
            packets = services.packets + excluded.packets,
            bytes = services.bytes + excluded.bytes,
            first_ts = MIN(COALESCE(services.first_ts, excluded.first_ts),
                           excluded.first_ts),
            last_ts = MAX(COALESCE(services.last_ts, excluded.last_ts),
                          excluded.last_ts)
        """,
        (capture_id, ip, port, proto, packets, length, first_ts, last_ts),
    )


def import_flowlogs(
    db: Database,
    path: Path,
    *,
    actor: str,
    fmt: str = "auto",
    label: str | None = None,
) -> dict:
    path = Path(path).expanduser()
    if not path.is_file():
        raise FlowlogError(f"file not found: {path}")
    if path.stat().st_size > 256 * 1024 * 1024:
        raise FlowlogError("flow-log file too large (limit 256 MiB)")
    text = path.read_text(errors="ignore")
    if fmt in ("", "auto"):
        fmt = detect_format(path)
    rows = parse_flowlogs(text, fmt)
    if not rows:
        raise FlowlogError("no usable flow records found in input")

    capture_id = _capture_id()
    name = (label or path.name)[:120]
    with db.connect() as conn:
        packets_store.create_capture(
            conn,
            capture_id=capture_id,
            created_at=_utcnow(),
            interface=None,
            profile="A",
            source="cloud-flowlog",
            bpf=None,
            original_filename=path.name,
        )
        flow_agg: dict[tuple, dict] = {}
        host_agg: dict[str, dict] = {}
        total_packets = total_bytes = 0
        for row in rows:
            key = (row["src"], row["dst"], row["proto"], row["dport"])
            agg = flow_agg.setdefault(
                key,
                {
                    "capture_id": capture_id,
                    "src": row["src"],
                    "dst": row["dst"],
                    "proto": row["proto"],
                    "dport": row["dport"],
                    "packets": 0,
                    "bytes": 0,
                    "first_ts": row["first_ts"],
                    "last_ts": row["last_ts"],
                },
            )
            agg["packets"] += row["packets"]
            agg["bytes"] += row["bytes"]
            if row["first_ts"] is not None:
                agg["first_ts"] = (
                    row["first_ts"]
                    if agg["first_ts"] is None
                    else min(agg["first_ts"], row["first_ts"])
                )
            if row["last_ts"] is not None:
                agg["last_ts"] = (
                    row["last_ts"]
                    if agg["last_ts"] is None
                    else max(agg["last_ts"], row["last_ts"])
                )
            src_host = host_agg.setdefault(
                row["src"],
                {"sent_packets": 0, "sent_bytes": 0, "recv_packets": 0,
                 "recv_bytes": 0, "first_ts": row["first_ts"],
                 "last_ts": row["last_ts"]},
            )
            dst_host = host_agg.setdefault(
                row["dst"],
                {"sent_packets": 0, "sent_bytes": 0, "recv_packets": 0,
                 "recv_bytes": 0, "first_ts": row["first_ts"],
                 "last_ts": row["last_ts"]},
            )
            src_host["sent_packets"] += row["packets"]
            src_host["sent_bytes"] += row["bytes"]
            dst_host["recv_packets"] += row["packets"]
            dst_host["recv_bytes"] += row["bytes"]
            for host in (src_host, dst_host):
                if row["first_ts"] is not None:
                    host["first_ts"] = (
                        row["first_ts"]
                        if host["first_ts"] is None
                        else min(host["first_ts"], row["first_ts"])
                    )
                if row["last_ts"] is not None:
                    host["last_ts"] = (
                        row["last_ts"]
                        if host["last_ts"] is None
                        else max(host["last_ts"], row["last_ts"])
                    )
            _bulk_service(
                conn,
                capture_id,
                row["dst"],
                row["dport"],
                row["proto"],
                row["packets"],
                row["bytes"],
                row["first_ts"],
                row["last_ts"],
            )
            total_packets += row["packets"]
            total_bytes += row["bytes"]

        packets_store.upsert_flows(conn, list(flow_agg.values()))
        for ip, stats in host_agg.items():
            _bulk_host(conn, capture_id, ip, **stats)
        packets_store.update_capture(
            conn,
            capture_id,
            status="ready",
            started_at=_utcnow(),
            stopped_at=_utcnow(),
            packets_captured=total_packets,
            bytes_written=total_bytes,
            original_filename=path.name,
        )
        append_event(
            conn,
            actor=actor,
            action="FLOWLOG_IMPORTED",
            target=capture_id,
            details={
                "format": fmt,
                "label": name,
                "records": len(rows),
                "packets": total_packets,
                "bytes": total_bytes,
                "source_file": path.name,
            },
        )
    return {
        "capture_id": capture_id,
        "format": fmt,
        "records": len(rows),
        "flows": len(flow_agg),
        "hosts": len(host_agg),
        "packets": total_packets,
        "bytes": total_bytes,
    }
