"""Web security analysis storage (spec sections 27-34).

Everything here is metadata. Token values are never stored: session analysis
uses HMAC-SHA256 fingerprints keyed with a per-install secret, so the same
token can be correlated across flows without the database ever holding a
recoverable token. The fingerprint key lives next to the vault key with 0600
permissions and is not derived from the token itself.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import sqlite3
from pathlib import Path
from typing import Any


TOKEN_ARTIFACT_TYPES = {
    "SESSION_COOKIE",
    "AUTH_COOKIE",
    "ACCESS_TOKEN",
    "REFRESH_TOKEN",
    "JWT",
    "BEARER_TOKEN",
    "CSRF_TOKEN",
    "OAUTH_ARTIFACT",
    "API_KEY",
}
AUTH_COOKIE_KINDS = {"SESSION_COOKIE", "AUTH_COOKIE", "ACCESS_TOKEN", "REFRESH_TOKEN"}
MAX_TRACKED_HOSTS = 16
MAX_TRACKED_CLIENTS = 16


def fingerprint_key(keys_dir: Path) -> bytes:
    keys_dir = Path(keys_dir)
    keys_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(keys_dir, 0o700)
    path = keys_dir / "fingerprint.key"
    if path.exists():
        return path.read_bytes()
    key = secrets.token_bytes(32)
    path.write_bytes(key)
    os.chmod(path, 0o600)
    return key


def token_fingerprint(key: bytes, value: str) -> str:
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def _json(items: Any) -> str | None:
    if not items:
        return None
    return json.dumps(sorted(set(items))[:64])


def record_token(
    conn: sqlite3.Connection,
    capture_id: str,
    item: dict,
    key: bytes,
) -> str | None:
    """Upsert fingerprint metadata for one collected sensitive artifact."""
    artifact_type = str(item.get("type") or "")
    if artifact_type not in TOKEN_ARTIFACT_TYPES:
        return None
    value = item.get("value")
    if not value:
        return None
    fingerprint = token_fingerprint(key, str(value))
    meta = item.get("meta") or {}
    jwt = meta.get("jwt") or {}
    host = item.get("host") or item.get("domain")
    client = item.get("src")
    ts = item.get("ts")
    plaintext = (item.get("transport_security") or "").lower() == "plaintext"
    name = meta.get("cookie_name") or item.get("field")
    conn.execute(
        """
        INSERT INTO web_tokens(capture_id, fingerprint, kind, name, alg, claims,
                               hosts, clients, plaintext, seen_count, first_ts,
                               last_ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        ON CONFLICT(capture_id, fingerprint) DO UPDATE SET
            hosts = COALESCE(?, web_tokens.hosts),
            clients = COALESCE(?, web_tokens.clients),
            plaintext = MAX(web_tokens.plaintext, excluded.plaintext),
            seen_count = web_tokens.seen_count + 1,
            first_ts = MIN(COALESCE(web_tokens.first_ts, excluded.first_ts),
                           COALESCE(excluded.first_ts, web_tokens.first_ts)),
            last_ts = MAX(COALESCE(web_tokens.last_ts, excluded.last_ts),
                          COALESCE(excluded.last_ts, web_tokens.last_ts))
        """,
        (
            capture_id,
            fingerprint,
            artifact_type,
            str(name)[:128] if name else None,
            jwt.get("alg"),
            json.dumps(jwt.get("claims") or {}) if jwt else None,
            _json([host]) if host else None,
            _json([client]) if client else None,
            int(plaintext),
            ts,
            ts,
            _merge_json(conn, capture_id, fingerprint, "hosts", host),
            _merge_json(conn, capture_id, fingerprint, "clients", client),
        ),
    )
    return fingerprint


def _merge_json(
    conn: sqlite3.Connection,
    capture_id: str,
    fingerprint: str,
    column: str,
    value: str | None,
) -> str | None:
    if not value:
        return None
    row = conn.execute(
        f"SELECT {column} AS value FROM web_tokens WHERE capture_id = ? "
        "AND fingerprint = ?",
        (capture_id, fingerprint),
    ).fetchone()
    current: list[str] = []
    if row and row["value"]:
        try:
            parsed = json.loads(row["value"])
            if isinstance(parsed, list):
                current = [str(item) for item in parsed]
        except json.JSONDecodeError:
            current = []
    if value not in current:
        current.append(value)
    return _json(current[:64])


# ----------------------------------------------------------------- listing


def list_cookies(conn: sqlite3.Connection, capture_id: str) -> dict:
    rows = conn.execute(
        """
        SELECT name, host, kind, set_observed, secure, http_only, same_site,
               domain, path, max_age, plaintext, seen_count, first_ts, last_ts
        FROM web_cookies WHERE capture_id = ?
        ORDER BY CASE WHEN kind = 'OTHER' THEN 1 ELSE 0 END, seen_count DESC, name
        """,
        (capture_id,),
    ).fetchall()
    return {"cookies": [dict(row) for row in rows]}


def list_headers(conn: sqlite3.Connection, capture_id: str) -> dict:
    rows = conn.execute(
        """
        SELECT host, responses, hsts, csp, x_content_type_options,
               x_frame_options, referrer_policy, permissions_policy,
               cache_control, server, first_ts, last_ts
        FROM web_headers WHERE capture_id = ? ORDER BY responses DESC, host
        """,
        (capture_id,),
    ).fetchall()
    return {"hosts": [dict(row) for row in rows]}


def list_tokens(conn: sqlite3.Connection, capture_id: str) -> dict:
    rows = conn.execute(
        """
        SELECT fingerprint, kind, name, alg, claims, hosts, clients, plaintext,
               seen_count, first_ts, last_ts
        FROM web_tokens WHERE capture_id = ? ORDER BY seen_count DESC, kind
        """,
        (capture_id,),
    ).fetchall()
    tokens = []
    for row in rows:
        record = dict(row)
        for field in ("hosts", "clients"):
            try:
                parsed = json.loads(record[field]) if record[field] else []
            except json.JSONDecodeError:
                parsed = []
            record[field] = parsed
        try:
            record["claims"] = json.loads(record["claims"]) if record["claims"] else {}
        except json.JSONDecodeError:
            record["claims"] = {}
        record["fingerprint"] = record["fingerprint"][:16]
        tokens.append(record)
    return {"tokens": tokens}


# ---------------------------------------------------------------- inventory


def _split_private(ips: list[str]) -> tuple[list[str], list[str]]:
    internal: list[str] = []
    external: list[str] = []
    for ip in ips:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if address.is_private or address.is_loopback or address.is_link_local:
            internal.append(ip)
        else:
            external.append(ip)
    return internal, external


def app_inventory(conn: sqlite3.Connection, capture_id: str) -> dict:
    """Per-host application inventory built from stored metadata only."""
    hosts: dict[str, dict] = {}

    def entry(host: str) -> dict:
        return hosts.setdefault(
            host,
            {
                "host": host,
                "ips": set(),
                "ports": set(),
                "dns_names": set(),
                "tls": [],
                "http_requests": 0,
                "http_responses": 0,
                "endpoints": set(),
                "auth_schemes": set(),
                "cookies": [],
                "tokens": 0,
                "security_headers": None,
                "findings": 0,
            },
        )

    for row in conn.execute(
        """
        SELECT host, src, dst, dport, method, path, auth_scheme, kind
        FROM http_events WHERE capture_id = ? AND host IS NOT NULL
        """,
        (capture_id,),
    ):
        host = row["host"]
        if not host:
            continue
        item = entry(host)
        server_ip = row["dst"] if row["kind"] == "request" else row["src"]
        if server_ip:
            item["ips"].add(server_ip)
        if row["dport"]:
            item["ports"].add(int(row["dport"]))
        if row["method"]:
            item["endpoints"].add(f"{row['method']} {row['path'] or '/'}")
        if row["auth_scheme"]:
            item["auth_schemes"].add(row["auth_scheme"])
        if row["kind"] == "request":
            item["http_requests"] += 1
        else:
            item["http_responses"] += 1

    for row in conn.execute(
        """
        SELECT sni, server, version, cipher, cert_not_before, cert_not_after,
               cert_sans, security
        FROM tls_sessions WHERE capture_id = ? AND sni IS NOT NULL
        """,
        (capture_id,),
    ):
        item = entry(row["sni"])
        if row["server"]:
            item["ips"].add(row["server"])
        item["tls"].append(
            {
                "version": row["version"],
                "cipher": row["cipher"],
                "not_before": row["cert_not_before"],
                "not_after": row["cert_not_after"],
                "sans": row["cert_sans"],
                "security": row["security"],
            }
        )

    for row in conn.execute(
        "SELECT qname, answers FROM dns_events WHERE capture_id = ?",
        (capture_id,),
    ):
        try:
            answers = json.loads(row["answers"]) if row["answers"] else []
        except json.JSONDecodeError:
            answers = []
        for host in list(hosts.keys()):
            if row["qname"] == host or row["qname"].endswith(f".{host}"):
                item = hosts[host]
                item["dns_names"].add(row["qname"])
                item["ips"].update(str(answer) for answer in answers[:8])

    for row in conn.execute(
        "SELECT host, name, kind FROM web_cookies WHERE capture_id = ?",
        (capture_id,),
    ):
        if row["host"] in hosts:
            hosts[row["host"]]["cookies"].append(
                {"name": row["name"], "kind": row["kind"]}
            )

    for row in conn.execute(
        "SELECT hosts FROM web_tokens WHERE capture_id = ?", (capture_id,)
    ):
        try:
            token_hosts = json.loads(row["hosts"]) if row["hosts"] else []
        except json.JSONDecodeError:
            token_hosts = []
        for host in token_hosts:
            if host in hosts:
                hosts[host]["tokens"] += 1

    for row in conn.execute(
        "SELECT * FROM web_headers WHERE capture_id = ?", (capture_id,)
    ):
        if row["host"] in hosts:
            hosts[row["host"]]["security_headers"] = {
                key: row[key]
                for key in (
                    "responses",
                    "hsts",
                    "csp",
                    "x_content_type_options",
                    "x_frame_options",
                    "referrer_policy",
                    "permissions_policy",
                    "cache_control",
                    "server",
                )
            }

    for row in conn.execute(
        "SELECT asset, COUNT(*) AS n FROM findings WHERE capture_id = ? "
        "AND asset IS NOT NULL GROUP BY asset",
        (capture_id,),
    ):
        if row["asset"] in hosts:
            hosts[row["asset"]]["findings"] = row["n"]

    applications = []
    for host, item in hosts.items():
        ips = sorted(item["ips"])
        internal, external = _split_private(ips)
        applications.append(
            {
                "host": host,
                "ips": ips,
                "internal_ips": internal,
                "external_ips": external,
                "ports": sorted(item["ports"]),
                "dns_names": sorted(item["dns_names"]),
                "tls": item["tls"][:16],
                "http_requests": item["http_requests"],
                "http_responses": item["http_responses"],
                "endpoints": sorted(item["endpoints"])[:64],
                "auth_schemes": sorted(item["auth_schemes"]),
                "cookies": item["cookies"][:32],
                "tokens": item["tokens"],
                "security_headers": item["security_headers"],
                "findings": item["findings"],
            }
        )
    applications.sort(key=lambda item: (-item["http_requests"], item["host"]))
    return {"applications": applications}


# --------------------------------------------------------------- data flow


def data_flows(conn: sqlite3.Connection, capture_id: str) -> dict:
    rows = conn.execute(
        """
        SELECT artifact_type, host, dst, transport_security, app_proto,
               http_method, path, COUNT(*) AS count, MIN(ts) AS first_ts,
               MAX(ts) AS last_ts
        FROM evidence WHERE capture_id = ?
        GROUP BY artifact_type, host, dst, transport_security, app_proto,
                 http_method, path
        ORDER BY count DESC
        """,
        (capture_id,),
    ).fetchall()
    flows = []
    for row in rows:
        destination = row["dst"]
        internal = None
        if destination:
            try:
                address = ipaddress.ip_address(destination)
                internal = (
                    address.is_private
                    or address.is_loopback
                    or address.is_link_local
                )
            except ValueError:
                internal = None
        transport = (row["transport_security"] or "unknown").lower()
        if transport == "plaintext":
            risk = "HIGH"
        elif transport == "encrypted" and internal is False:
            risk = "MEDIUM"
        else:
            risk = "LOW"
        flows.append(
            {
                **dict(row),
                "destination_internal": internal,
                "transport_risk": risk,
            }
        )
    return {"flows": flows}
