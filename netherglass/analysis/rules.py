"""Security detection engine: configurable rules over stored metadata.

Rules only operate on data already stored by earlier stages (packets, flows,
DNS/HTTP/TLS events, hosts, sealed evidence metadata). Sensitive values are
never consulted: rules key off artifact metadata (type, field, endpoints,
transport security), never the value itself.

Configuration: every rule is enable/disable-able and severity-adjustable via
<data_dir>/rules.json:

    {"rules": {"weak_tls": {"enabled": false, "severity": "MEDIUM"}}}

Honesty rules: every finding carries a confidence from the mandated
vocabulary, and every explanation states the observation it is based on.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ..store import findings as findings_store

SEVERITIES = findings_store.SEVERITIES

PRIVATE_SERVICE_PORTS = (23, 445, 139, 3389, 5900)
CRITICAL_ARTIFACT_TYPES = {
    "PASSWORD",
    "BASIC_AUTH",
    "PRIVATE_KEY",
    "CLOUD_CREDENTIAL",
    "DATABASE_CREDENTIAL",
}
PLAINTEXT_CREDENTIAL_TYPES = (
    "PASSWORD",
    "BASIC_AUTH",
    "BEARER_TOKEN",
    "ACCESS_TOKEN",
    "REFRESH_TOKEN",
    "JWT",
    "API_KEY",
    "SESSION_COOKIE",
    "AUTH_COOKIE",
    "CSRF_TOKEN",
    "OAUTH_ARTIFACT",
    "PRIVATE_KEY",
    "CLOUD_CREDENTIAL",
    "DATABASE_CREDENTIAL",
    "UNKNOWN_SECRET",
)
WEAK_CIPHER_SQL = (
    "UPPER(cipher) LIKE '%RC4%' OR UPPER(cipher) LIKE '%3DES%' "
    "OR UPPER(cipher) LIKE '%CBC%' OR UPPER(cipher) LIKE '%NULL%' "
    "OR UPPER(cipher) LIKE '%EXPORT%'"
)
URL_TOKEN_NAMES = ("token", "session", "sid", "auth", "apikey", "api_key", "jwt")


@dataclass
class RuleContext:
    conn: sqlite3.Connection
    capture_id: str
    now: datetime
    overrides: dict


@dataclass(frozen=True)
class Rule:
    id: str
    version: int
    title: str
    severity: str
    confidence: str
    description: str
    remediation: str
    check: Callable[[RuleContext], list[dict]]
    enabled: bool = True


def _is_private(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


def _rows(ctx: RuleContext, sql: str, params: tuple = ()) -> list[dict]:
    return [
        dict(row)
        for row in ctx.conn.execute(sql, (ctx.capture_id, *params)).fetchall()
    ]


def _parse_cert_time(text: Any) -> datetime | None:
    if not text:
        return None
    cleaned = str(text).strip().replace(".0Z", "Z")
    for fmt in ("%y%m%d%H%M%SZ", "%Y%m%d%H%M%SZ"):
        try:
            return datetime.strptime(cleaned, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
    except ValueError:
        return None


# ------------------------------------------------------------------ rules


def _rule_plaintext_credentials(ctx: RuleContext) -> list[dict]:
    placeholders = ",".join("?" for _ in PLAINTEXT_CREDENTIAL_TYPES)
    rows = _rows(
        ctx,
        f"""
        SELECT id, artifact_type, field, src, dst, host, path, protocol, ts,
               stream, frame
        FROM evidence
        WHERE capture_id = ? AND transport_security = 'plaintext'
          AND artifact_type IN ({placeholders})
        ORDER BY ts, id LIMIT 50
        """,
        tuple(PLAINTEXT_CREDENTIAL_TYPES),
    )
    out = []
    for row in rows:
        target = row.get("host") or row.get("dst") or "unknown destination"
        where = f"{row.get('protocol') or 'HTTP'} to {target}"
        if row.get("path"):
            where += f" ({row['path']})"
        out.append(
            {
                "severity": "CRITICAL"
                if row["artifact_type"] in CRITICAL_ARTIFACT_TYPES
                else "HIGH",
                "confidence": "OBSERVED",
                "explanation": (
                    f"{row['artifact_type']} observed in cleartext {where} "
                    f"({row.get('field') or 'unknown field'})"
                ),
                "asset": row.get("src"),
                "src": row.get("src"),
                "dst": row.get("dst"),
                "protocol": row.get("protocol"),
                "first_ts": row.get("ts"),
                "last_ts": row.get("ts"),
                "evidence_ids": [row["id"]],
                "packet_refs": [row["frame"]] if row.get("frame") else [],
            }
        )
    return out


def _rule_weak_tls(ctx: RuleContext) -> list[dict]:
    rows = _rows(
        ctx,
        f"""
        SELECT stream, client, server, version, cipher, first_ts, last_ts
        FROM tls_sessions
        WHERE capture_id = ?
          AND (version IN ('TLS1.0', 'TLS1.1', 'SSLv3')
               OR (cipher IS NOT NULL AND ({WEAK_CIPHER_SQL})))
        ORDER BY first_ts LIMIT 50
        """,
    )
    out = []
    for row in rows:
        parts = []
        if row.get("version"):
            parts.append(f"version {row['version']}")
        if row.get("cipher"):
            parts.append(f"cipher {row['cipher']}")
        out.append(
            {
                "severity": "CRITICAL" if row.get("version") == "SSLv3" else "HIGH",
                "confidence": "OBSERVED",
                "explanation": "Observed TLS session with " + (", ".join(parts) or "weak parameters"),
                "asset": row.get("server"),
                "src": row.get("client"),
                "dst": row.get("server"),
                "protocol": "tls",
                "first_ts": row.get("first_ts"),
                "last_ts": row.get("last_ts"),
                "evidence_ids": [],
                "packet_refs": [],
            }
        )
    return out


def _rule_cleartext_protocols(ctx: RuleContext) -> list[dict]:
    rows = _rows(
        ctx,
        """
        SELECT src, dst, COALESCE(app_proto, proto) AS app, COUNT(*) AS packets,
               MIN(ts) AS first_ts, MAX(ts) AS last_ts
        FROM packets
        WHERE capture_id = ?
          AND (app_proto IN ('ftp', 'telnet') OR proto IN ('ftp', 'telnet')
               OR dport IN (21, 23))
        GROUP BY src, dst, app
        ORDER BY packets DESC LIMIT 50
        """,
    )
    return [
        {
            "severity": "MEDIUM",
            "confidence": "OBSERVED",
            "explanation": (
                f"Observed {row['packets']} {row['app']} packet(s) between "
                f"{row['src']} and {row['dst']}; {row['app']} transmits "
                "credentials and data in cleartext"
            ),
            "asset": row.get("src"),
            "src": row.get("src"),
            "dst": row.get("dst"),
            "protocol": row.get("app"),
            "first_ts": row.get("first_ts"),
            "last_ts": row.get("last_ts"),
            "evidence_ids": [],
            "packet_refs": [],
        }
        for row in rows
    ]


def _rule_session_token_in_url(ctx: RuleContext) -> list[dict]:
    conditions = " OR ".join(
        "LOWER(query_names) LIKE ?" for _ in URL_TOKEN_NAMES
    )
    params = tuple(f"%{name}%" for name in URL_TOKEN_NAMES)
    rows = _rows(
        ctx,
        f"""
        SELECT src, dst, host, path, query_names, ts
        FROM http_events
        WHERE capture_id = ? AND kind = 'request' AND query_names IS NOT NULL
          AND ({conditions})
        ORDER BY ts LIMIT 20
        """,
        params,
    )
    return [
        {
            "severity": "MEDIUM",
            "confidence": "POSSIBLE",
            "explanation": (
                f"URL query parameter name(s) {row['query_names']} on "
                f"{row.get('host') or row.get('dst')}{row.get('path') or ''} "
                "resemble session/token carriers; values are not inspected"
            ),
            "asset": row.get("src"),
            "src": row.get("src"),
            "dst": row.get("dst"),
            "protocol": "http",
            "first_ts": row.get("ts"),
            "last_ts": row.get("ts"),
            "evidence_ids": [],
            "packet_refs": [],
        }
        for row in rows
    ]


def _rule_authorization_in_cleartext(ctx: RuleContext) -> list[dict]:
    rows = _rows(
        ctx,
        """
        SELECT DISTINCT src, dst, host, auth_scheme, ts
        FROM http_events
        WHERE capture_id = ? AND auth_scheme IS NOT NULL
          AND (dport IS NULL OR dport NOT IN (443, 8443))
        ORDER BY ts LIMIT 20
        """,
    )
    return [
        {
            "severity": "HIGH",
            "confidence": "LIKELY",
            "explanation": (
                f"Authorization header with scheme {row.get('auth_scheme')} "
                f"observed on cleartext HTTP to "
                f"{row.get('host') or row.get('dst')}; the credential itself "
                "is sealed in the evidence vault (if retained)"
            ),
            "asset": row.get("src"),
            "src": row.get("src"),
            "dst": row.get("dst"),
            "protocol": "http",
            "first_ts": row.get("ts"),
            "last_ts": row.get("ts"),
            "evidence_ids": [],
            "packet_refs": [],
        }
        for row in rows
    ]


def _rule_unexpected_dns_server(ctx: RuleContext) -> list[dict]:
    rows = _rows(
        ctx,
        """
        SELECT server, COUNT(DISTINCT client) AS clients, COUNT(*) AS queries,
               MIN(ts) AS first_ts, MAX(ts) AS last_ts
        FROM dns_events
        WHERE capture_id = ? AND server IS NOT NULL
        GROUP BY server ORDER BY queries DESC LIMIT 200
        """,
    )
    out = []
    for row in rows:
        if _is_private(row.get("server")):
            continue
        out.append(
            {
                "severity": "MEDIUM",
                "confidence": "LIKELY",
                "explanation": (
                    f"DNS server {row['server']} is not a private or loopback "
                    f"address; {row['queries']} queries from "
                    f"{row['clients']} client(s). Configure expected resolvers "
                    "in rules.json if this is intentional"
                ),
                "asset": row.get("server"),
                "src": None,
                "dst": row.get("server"),
                "protocol": "dns",
                "first_ts": row.get("first_ts"),
                "last_ts": row.get("last_ts"),
                "evidence_ids": [],
                "packet_refs": [],
            }
        )
    return out[:20]


def _rule_suspicious_dns(ctx: RuleContext) -> list[dict]:
    rows = _rows(
        ctx,
        """
        SELECT client, COUNT(*) AS queries,
               SUM(CASE WHEN rcode = 'NXDOMAIN' THEN 1 ELSE 0 END) AS nxdomain,
               MIN(ts) AS first_ts, MAX(ts) AS last_ts
        FROM dns_events
        WHERE capture_id = ? AND matched IN (0, 1) AND client IS NOT NULL
        GROUP BY client
        HAVING queries >= 20 AND nxdomain * 3 >= queries
        ORDER BY nxdomain DESC LIMIT 10
        """,
    )
    return [
        {
            "severity": "MEDIUM",
            "confidence": "POSSIBLE",
            "explanation": (
                f"Client {row['client']} sent {row['queries']} DNS queries of "
                f"which {row['nxdomain']} were NXDOMAIN; a high failure rate "
                "can indicate DGA activity or misconfiguration"
            ),
            "asset": row.get("client"),
            "src": row.get("client"),
            "dst": None,
            "protocol": "dns",
            "first_ts": row.get("first_ts"),
            "last_ts": row.get("last_ts"),
            "evidence_ids": [],
            "packet_refs": [],
        }
        for row in rows
    ]


def _rule_dns_tunneling_indicator(ctx: RuleContext) -> list[dict]:
    rows = _rows(
        ctx,
        """
        SELECT qname, client, COUNT(*) AS queries, MIN(ts) AS first_ts,
               MAX(ts) AS last_ts
        FROM dns_events
        WHERE capture_id = ? AND LENGTH(qname) >= 50 AND client IS NOT NULL
        GROUP BY qname, client HAVING queries >= 5
        ORDER BY queries DESC LIMIT 20
        """,
    )
    return [
        {
            "severity": "MEDIUM",
            "confidence": "POSSIBLE",
            "explanation": (
                f"Unusually long DNS name observed {row['queries']} times from "
                f"{row['client']} (length {len(row['qname'])}); long random "
                "labels repeated can indicate DNS tunneling"
            ),
            "asset": row.get("client"),
            "src": row.get("client"),
            "dst": None,
            "protocol": "dns",
            "first_ts": row.get("first_ts"),
            "last_ts": row.get("last_ts"),
            "evidence_ids": [],
            "packet_refs": [],
        }
        for row in rows
    ]


def _rule_unexpected_external_service(ctx: RuleContext) -> list[dict]:
    placeholders = ",".join("?" for _ in PRIVATE_SERVICE_PORTS)
    rows = _rows(
        ctx,
        f"""
        SELECT src, dst, dport, COUNT(*) AS packets, MIN(ts) AS first_ts,
               MAX(ts) AS last_ts
        FROM packets
        WHERE capture_id = ? AND proto = 'tcp' AND dport IN ({placeholders})
        GROUP BY src, dst, dport ORDER BY packets DESC LIMIT 100
        """,
        tuple(PRIVATE_SERVICE_PORTS),
    )
    out = []
    for row in rows:
        if not (_is_private(row.get("src")) and not _is_private(row.get("dst"))):
            continue
        out.append(
            {
                "severity": "HIGH",
                "confidence": "LIKELY",
                "explanation": (
                    f"Internal host {row['src']} contacted public address "
                    f"{row['dst']} on port {row['dport']} "
                    f"({row['packets']} packets); remote administration "
                    "protocols should not cross the network boundary"
                ),
                "asset": row.get("src"),
                "src": row.get("src"),
                "dst": row.get("dst"),
                "protocol": "tcp",
                "first_ts": row.get("first_ts"),
                "last_ts": row.get("last_ts"),
                "evidence_ids": [],
                "packet_refs": [],
            }
        )
    return out[:20]


def _rule_port_scan_indicator(ctx: RuleContext) -> list[dict]:
    rows = _rows(
        ctx,
        """
        SELECT src, dst, COUNT(DISTINCT dport) AS ports, COUNT(*) AS packets,
               MIN(ts) AS first_ts, MAX(ts) AS last_ts
        FROM packets
        WHERE capture_id = ? AND proto = 'tcp' AND dport IS NOT NULL
        GROUP BY src, dst
        HAVING ports >= 20 AND (MAX(ts) - MIN(ts)) <= 120
        ORDER BY ports DESC LIMIT 20
        """,
    )
    return [
        {
            "severity": "MEDIUM",
            "confidence": "POSSIBLE",
            "explanation": (
                f"{row['src']} contacted {row['ports']} distinct TCP ports on "
                f"{row['dst']} within a short window; this pattern resembles "
                "port scanning (or a very active health-checking tool)"
            ),
            "asset": row.get("src"),
            "src": row.get("src"),
            "dst": row.get("dst"),
            "protocol": "tcp",
            "first_ts": row.get("first_ts"),
            "last_ts": row.get("last_ts"),
            "evidence_ids": [],
            "packet_refs": [],
        }
        for row in rows
    ]


def _rule_unusual_traffic_volume(ctx: RuleContext) -> list[dict]:
    rows = _rows(
        ctx,
        """
        SELECT ip, hostname, sent_bytes, sent_packets
        FROM hosts WHERE capture_id = ?
        ORDER BY sent_bytes DESC LIMIT 200
        """,
    )
    if len(rows) < 5:
        return []
    volumes = sorted(row["sent_bytes"] or 0 for row in rows)
    median = volumes[len(volumes) // 2]
    threshold = max(10 * 1024 * 1024, median * 10)
    out = []
    for row in rows[:3]:
        sent = row.get("sent_bytes") or 0
        if sent <= threshold:
            continue
        out.append(
            {
                "severity": "MEDIUM",
                "confidence": "POSSIBLE",
                "explanation": (
                    f"Host {row['ip']} sent {sent} bytes, far above the "
                    f"capture median ({median} bytes); unusual uplink volume "
                    "warrants a look (backups and updates can look like this)"
                ),
                "asset": row.get("ip"),
                "src": row.get("ip"),
                "dst": None,
                "protocol": None,
                "first_ts": None,
                "last_ts": None,
                "evidence_ids": [],
                "packet_refs": [],
            }
        )
    return out


def _rule_possible_exfiltration(ctx: RuleContext) -> list[dict]:
    rows = _rows(
        ctx,
        """
        SELECT src, dst, COUNT(*) AS packets, SUM(length) AS bytes,
               MIN(ts) AS first_ts, MAX(ts) AS last_ts
        FROM packets WHERE capture_id = ?
        GROUP BY src, dst ORDER BY bytes DESC LIMIT 50
        """,
    )
    out = []
    for row in rows:
        if not (_is_private(row.get("src")) and not _is_private(row.get("dst"))):
            continue
        if (row.get("bytes") or 0) < 50 * 1024 * 1024:
            continue
        out.append(
            {
                "severity": "HIGH",
                "confidence": "POSSIBLE",
                "explanation": (
                    f"{row['bytes']} bytes sent from internal host {row['src']} "
                    f"to public address {row['dst']}; large outbound transfers "
                    "can indicate data exfiltration"
                ),
                "asset": row.get("src"),
                "src": row.get("src"),
                "dst": row.get("dst"),
                "protocol": None,
                "first_ts": row.get("first_ts"),
                "last_ts": row.get("last_ts"),
                "evidence_ids": [],
                "packet_refs": [],
            }
        )
        if len(out) >= 5:
            break
    return out


def _rule_possible_tunneling(ctx: RuleContext) -> list[dict]:
    rows = _rows(
        ctx,
        """
        SELECT src, dst, COALESCE(app_proto, proto) AS app, dport,
               COUNT(*) AS packets, MIN(ts) AS first_ts, MAX(ts) AS last_ts
        FROM packets
        WHERE capture_id = ?
          AND (app_proto IN ('wireguard', 'openvpn', 'esp', 'isakmp')
               OR (proto = 'udp' AND (dport IN (500, 4500, 1194, 51820)
                                      OR sport IN (500, 4500, 1194, 51820)))
               OR (proto = 'tcp' AND dport = 53))
        GROUP BY src, dst, app, dport ORDER BY packets DESC LIMIT 20
        """,
    )
    return [
        {
            "severity": "MEDIUM",
            "confidence": "POSSIBLE",
            "explanation": (
                f"{row['app']} traffic observed between {row['src']} and "
                f"{row['dst']} ({row['packets']} packets); tunnels can be "
                "legitimate or can bypass inspection controls"
            ),
            "asset": row.get("src"),
            "src": row.get("src"),
            "dst": row.get("dst"),
            "protocol": row.get("app"),
            "first_ts": row.get("first_ts"),
            "last_ts": row.get("last_ts"),
            "evidence_ids": [],
            "packet_refs": [],
        }
        for row in rows
    ]


def _rule_unencrypted_tunnel(ctx: RuleContext) -> list[dict]:
    rows = _rows(
        ctx,
        """
        SELECT tunnel_proto, src, dst, sport, dport, state, inner_visible,
               packets, bytes, first_ts, last_ts
        FROM tunnels
        WHERE capture_id = ? AND inner_visible = 1
        ORDER BY bytes DESC LIMIT 20
        """,
    )
    findings = []
    for row in rows:
        internal = _is_private(row["dst"]) and _is_private(row["src"])
        peer = "internal endpoints" if internal else "at least one non-private endpoint"
        findings.append(
            {
                "severity": "MEDIUM",
                "confidence": "OBSERVED",
                "explanation": (
                    f"unencrypted encapsulation {row['tunnel_proto']} observed "
                    f"between {row['src']} and {row['dst']} ({row['packets']} "
                    f"packets, {row['bytes']} bytes, {peer}); encapsulated "
                    "traffic may bypass inspection controls"
                ),
                "asset": row.get("src"),
                "src": row.get("src"),
                "dst": row.get("dst"),
                "protocol": row.get("tunnel_proto"),
                "first_ts": row.get("first_ts"),
                "last_ts": row.get("last_ts"),
                "evidence_ids": [],
                "packet_refs": [],
            }
        )
    return findings


def _rule_auth_anomaly(ctx: RuleContext) -> list[dict]:
    rows = _rows(
        ctx,
        """
        SELECT src, dst, status, COUNT(*) AS responses, MIN(ts) AS first_ts,
               MAX(ts) AS last_ts
        FROM http_events
        WHERE capture_id = ? AND kind = 'response' AND status IN (401, 403)
        GROUP BY src, dst, status HAVING responses >= 10
        ORDER BY responses DESC LIMIT 20
        """,
    )
    return [
        {
            "severity": "MEDIUM",
            "confidence": "POSSIBLE",
            "explanation": (
                f"{row['responses']} HTTP {row['status']} responses from "
                f"{row['src']}; repeated authorization failures can indicate "
                "credential guessing or a broken client"
            ),
            "asset": row.get("src"),
            "src": row.get("src"),
            "dst": row.get("dst"),
            "protocol": "http",
            "first_ts": row.get("first_ts"),
            "last_ts": row.get("last_ts"),
            "evidence_ids": [],
            "packet_refs": [],
        }
        for row in rows
    ]


def _rule_certificate_validity(ctx: RuleContext) -> list[dict]:
    rows = _rows(
        ctx,
        """
        SELECT stream, client, server, cert_not_before, cert_not_after
        FROM tls_sessions
        WHERE capture_id = ?
          AND (cert_not_before IS NOT NULL OR cert_not_after IS NOT NULL)
        LIMIT 200
        """,
    )
    out = []
    for row in rows:
        not_after = _parse_cert_time(row.get("cert_not_after"))
        not_before = _parse_cert_time(row.get("cert_not_before"))
        if not_after is not None and not_after < ctx.now:
            out.append(
                {
                    "severity": "HIGH",
                    "confidence": "OBSERVED",
                    "explanation": (
                        f"Certificate for {row.get('server') or row.get('stream')} "
                        f"expired at {not_after.isoformat(timespec='seconds')}"
                    ),
                    "asset": row.get("server"),
                    "src": row.get("client"),
                    "dst": row.get("server"),
                    "protocol": "tls",
                    "first_ts": None,
                    "last_ts": None,
                    "evidence_ids": [],
                    "packet_refs": [],
                }
            )
        elif not_before is not None and not_before > ctx.now:
            out.append(
                {
                    "severity": "MEDIUM",
                    "confidence": "LIKELY",
                    "explanation": (
                        f"Certificate for {row.get('server') or row.get('stream')} "
                        f"is not valid until {not_before.isoformat(timespec='seconds')}"
                    ),
                    "asset": row.get("server"),
                    "src": row.get("client"),
                    "dst": row.get("server"),
                    "protocol": "tls",
                    "first_ts": None,
                    "last_ts": None,
                    "evidence_ids": [],
                    "packet_refs": [],
                }
            )
    return out[:20]


def _rule_cookie_attributes(ctx: RuleContext) -> list[dict]:
    rows = _rows(
        ctx,
        """
        SELECT name, host, kind, secure, http_only, same_site, max_age, plaintext
        FROM web_cookies
        WHERE capture_id = ? AND kind IN ('SESSION_COOKIE', 'AUTH_COOKIE',
                                          'ACCESS_TOKEN', 'REFRESH_TOKEN')
        ORDER BY seen_count DESC LIMIT 50
        """,
    )
    out = []
    for row in rows:
        issues = []
        if not row["secure"]:
            issues.append("missing Secure")
        if not row["http_only"]:
            issues.append("missing HttpOnly")
        same_site = (row.get("same_site") or "").lower()
        if same_site not in ("strict", "lax"):
            issues.append(f"SameSite={row.get('same_site') or 'absent'}")
        if row.get("max_age") and int(row["max_age"]) > 86400 * 30:
            issues.append(f"Max-Age {int(row['max_age'])}s (>30 days)")
        if not issues:
            continue
        severity = "HIGH" if row["plaintext"] else "MEDIUM"
        out.append(
            {
                "severity": severity,
                "confidence": "OBSERVED",
                "explanation": (
                    f"Authentication-related cookie '{row['name']}' on "
                    f"{row['host'] or 'unknown host'} is set with "
                    f"{', '.join(issues)}"
                    + (" and was observed over plaintext HTTP" if row["plaintext"] else "")
                ),
                "asset": row["host"],
                "src": None,
                "dst": None,
                "protocol": "http",
                "first_ts": None,
                "last_ts": None,
                "evidence_ids": [],
                "packet_refs": [],
            }
        )
    return out


def _rule_missing_security_headers(ctx: RuleContext) -> list[dict]:
    rows = _rows(
        ctx,
        """
        SELECT host, responses, hsts, csp, x_content_type_options,
               x_frame_options, referrer_policy
        FROM web_headers WHERE capture_id = ? AND responses > 0
        ORDER BY responses DESC LIMIT 50
        """,
    )
    out = []
    for row in rows:
        missing = [
            label
            for label, present in (
                ("Strict-Transport-Security", row["hsts"]),
                ("Content-Security-Policy", row["csp"]),
                ("X-Content-Type-Options", row["x_content_type_options"]),
                ("X-Frame-Options/frame-ancestors", row["x_frame_options"]),
                ("Referrer-Policy", row["referrer_policy"]),
            )
            if not present
        ]
        if not missing:
            continue
        out.append(
            {
                "severity": "LOW",
                "confidence": "OBSERVED",
                "explanation": (
                    f"{row['responses']} HTTP response(s) from {row['host']} "
                    f"were observed without: {', '.join(missing)}"
                ),
                "asset": row["host"],
                "src": None,
                "dst": None,
                "protocol": "http",
                "first_ts": None,
                "last_ts": None,
                "evidence_ids": [],
                "packet_refs": [],
            }
        )
    return out


def _rule_cookie_over_plaintext(ctx: RuleContext) -> list[dict]:
    rows = _rows(
        ctx,
        """
        SELECT name, host, kind, plaintext, seen_count
        FROM web_cookies WHERE capture_id = ? AND plaintext = 1
        ORDER BY seen_count DESC LIMIT 30
        """,
    )
    return [
        {
            "severity": "HIGH" if row["kind"] != "OTHER" else "MEDIUM",
            "confidence": "OBSERVED",
            "explanation": (
                f"Cookie '{row['name']}' on {row['host'] or 'unknown host'} was "
                f"observed over plaintext HTTP ({row['seen_count']} time(s)); "
                "any network observer can read or replay it"
            ),
            "asset": row["host"],
            "src": None,
            "dst": None,
            "protocol": "http",
            "first_ts": None,
            "last_ts": None,
            "evidence_ids": [],
            "packet_refs": [],
        }
        for row in rows
    ]


def _rule_token_boundary(ctx: RuleContext) -> list[dict]:
    rows = _rows(
        ctx,
        """
        SELECT kind, name, hosts, clients, plaintext, seen_count
        FROM web_tokens WHERE capture_id = ?
        ORDER BY seen_count DESC LIMIT 100
        """,
    )
    out = []
    for row in rows:
        try:
            hosts = json.loads(row["hosts"]) if row["hosts"] else []
        except json.JSONDecodeError:
            hosts = []
        try:
            clients = json.loads(row["clients"]) if row["clients"] else []
        except json.JSONDecodeError:
            clients = []
        if len(hosts) > 1:
            out.append(
                {
                    "severity": "MEDIUM",
                    "confidence": "LIKELY",
                    "explanation": (
                        f"A {row['kind']} credential was observed on {len(hosts)} "
                        f"distinct hosts ({', '.join(hosts[:6])}); this can "
                        "indicate credential reuse across security boundaries"
                    ),
                    "asset": hosts[0],
                    "src": clients[0] if clients else None,
                    "dst": None,
                    "protocol": "http",
                    "first_ts": None,
                    "last_ts": None,
                    "evidence_ids": [],
                    "packet_refs": [],
                }
            )
        elif len(clients) > 1:
            out.append(
                {
                    "severity": "MEDIUM",
                    "confidence": "LIKELY",
                    "explanation": (
                        f"The same {row['kind']} credential was observed from "
                        f"{len(clients)} different client addresses "
                        f"({', '.join(clients[:6])}) toward {hosts[0] if hosts else 'one host'}; "
                        "verify whether session sharing is expected"
                    ),
                    "asset": hosts[0] if hosts else None,
                    "src": clients[0],
                    "dst": None,
                    "protocol": "http",
                    "first_ts": None,
                    "last_ts": None,
                    "evidence_ids": [],
                    "packet_refs": [],
                }
            )
    return out[:20]


def _rule_long_lived_token(ctx: RuleContext) -> list[dict]:
    rows = _rows(
        ctx,
        """
        SELECT kind, name, claims, hosts FROM web_tokens
        WHERE capture_id = ? AND claims IS NOT NULL LIMIT 100
        """,
    )
    out = []
    now = ctx.now.timestamp()
    for row in rows:
        try:
            claims = json.loads(row["claims"]) if row["claims"] else {}
        except json.JSONDecodeError:
            continue
        exp = claims.get("exp")
        iat = claims.get("iat")
        if not isinstance(exp, (int, float)) or not isinstance(iat, (int, float)):
            continue
        lifetime = exp - iat
        if lifetime > 86400 * 30 and exp > now:
            try:
                hosts = json.loads(row["hosts"]) if row["hosts"] else []
            except json.JSONDecodeError:
                hosts = []
            out.append(
                {
                    "severity": "MEDIUM",
                    "confidence": "OBSERVED",
                    "explanation": (
                        f"{row['kind']} '{row['name'] or 'token'}' has a "
                        f"{int(lifetime / 86400)}-day lifetime (iat→exp) on "
                        f"{hosts[0] if hosts else 'unknown host'}; long-lived "
                        "bearer tokens widen the replay window"
                    ),
                    "asset": hosts[0] if hosts else None,
                    "src": None,
                    "dst": None,
                    "protocol": "http",
                    "first_ts": None,
                    "last_ts": None,
                    "evidence_ids": [],
                    "packet_refs": [],
                }
            )
    return out[:20]


def _rule_http_not_https(ctx: RuleContext) -> list[dict]:
    rows = _rows(
        ctx,
        """
        SELECT host, COUNT(*) AS requests, MIN(ts) AS first_ts,
               MAX(ts) AS last_ts
        FROM http_events
        WHERE capture_id = ? AND kind = 'request' AND host IS NOT NULL
          AND (dport IS NULL OR dport NOT IN (443, 8443))
        GROUP BY host ORDER BY requests DESC LIMIT 50
        """,
    )
    return [
        {
            "severity": "MEDIUM",
            "confidence": "OBSERVED",
            "explanation": (
                f"{row['requests']} HTTP request(s) to {row['host']} were "
                "observed on a non-TLS port; request paths, cookies and "
                "headers are visible to any network observer"
            ),
            "asset": row["host"],
            "src": None,
            "dst": None,
            "protocol": "http",
            "first_ts": row["first_ts"],
            "last_ts": row["last_ts"],
            "evidence_ids": [],
            "packet_refs": [],
        }
        for row in rows
    ]


def _rule_sensitive_to_external(ctx: RuleContext) -> list[dict]:
    rows = _rows(
        ctx,
        """
        SELECT artifact_type, field, host, dst, src, transport_security, ts,
               COUNT(*) AS n
        FROM evidence
        WHERE capture_id = ? AND dst IS NOT NULL
        GROUP BY artifact_type, field, host, dst, src, transport_security, ts
        ORDER BY ts LIMIT 200
        """,
    )
    out = []
    for row in rows:
        if _is_private(row.get("dst")) or not row.get("dst"):
            continue
        transport = (row.get("transport_security") or "").lower()
        out.append(
            {
                "severity": "HIGH" if transport == "plaintext" else "MEDIUM",
                "confidence": "OBSERVED",
                "explanation": (
                    f"{row['artifact_type']} ({row.get('field') or 'unknown field'}) "
                    f"was sent to public address {row['dst']}"
                    + (f" ({row['host']})" if row.get("host") else "")
                    + f" over {transport or 'unknown'} transport; verify the "
                    "destination is an expected third party"
                ),
                "asset": row.get("src"),
                "src": row.get("src"),
                "dst": row.get("dst"),
                "protocol": "http" if row.get("host") else None,
                "first_ts": row.get("ts"),
                "last_ts": row.get("ts"),
                "evidence_ids": [],
                "packet_refs": [],
            }
        )
    return out[:20]


RULES: list[Rule] = [
    Rule(
        id="cookie_attributes",
        version=1,
        title="Authentication Cookie Missing Security Attributes",
        severity="MEDIUM",
        confidence="OBSERVED",
        description=(
            "An authentication-related cookie was observed without Secure, "
            "HttpOnly or an adequate SameSite policy."
        ),
        remediation=(
            "Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies; "
            "keep authentication cookie lifetimes short."
        ),
        check=_rule_cookie_attributes,
    ),
    Rule(
        id="cookie_over_plaintext",
        version=1,
        title="Cookie Sent Over Plaintext HTTP",
        severity="HIGH",
        confidence="OBSERVED",
        description="A cookie was observed on a cleartext HTTP flow.",
        remediation=(
            "Serve all cookie-bearing endpoints over HTTPS and mark cookies "
            "Secure; rotate cookies that may have been exposed."
        ),
        check=_rule_cookie_over_plaintext,
    ),
    Rule(
        id="missing_security_headers",
        version=1,
        title="Missing HTTP Security Headers",
        severity="LOW",
        confidence="OBSERVED",
        description=(
            "HTTP responses were observed without common defensive headers "
            "(HSTS, CSP, nosniff, frame protections, Referrer-Policy)."
        ),
        remediation=(
            "Add Strict-Transport-Security, Content-Security-Policy, "
            "X-Content-Type-Options, frame protections and Referrer-Policy at "
            "the application or reverse proxy."
        ),
        check=_rule_missing_security_headers,
    ),
    Rule(
        id="token_boundary",
        version=1,
        title="Authentication Artifact Crossing Boundaries",
        severity="MEDIUM",
        confidence="LIKELY",
        description=(
            "The same authentication artifact fingerprint was observed on "
            "multiple hosts or from multiple client addresses."
        ),
        remediation=(
            "Scope sessions to a single host and client; investigate shared or "
            "replayed session material and shorten token lifetimes."
        ),
        check=_rule_token_boundary,
    ),
    Rule(
        id="long_lived_token",
        version=1,
        title="Long-Lived Authentication Token",
        severity="MEDIUM",
        confidence="OBSERVED",
        description="A JWT with a lifetime longer than 30 days was observed.",
        remediation=(
            "Reduce token lifetimes and use refresh tokens with rotation; "
            "revocation must be possible for stolen bearer tokens."
        ),
        check=_rule_long_lived_token,
    ),
    Rule(
        id="http_not_https",
        version=1,
        title="Application Traffic Sent Over Cleartext HTTP",
        severity="MEDIUM",
        confidence="OBSERVED",
        description=(
            "HTTP packets to a host were classified as cleartext; request "
            "metadata is visible to any network observer."
        ),
        remediation=(
            "Redirect HTTP to HTTPS, enable HSTS, and remove any endpoint that "
            "serves authentication or session traffic without TLS."
        ),
        check=_rule_http_not_https,
    ),
    Rule(
        id="sensitive_to_external",
        version=1,
        title="Sensitive Artifact Sent to Public Address",
        severity="HIGH",
        confidence="OBSERVED",
        description=(
            "A sensitive artifact was observed flowing to a public (non-private) "
            "destination; third-party transmission should be expected and authorized."
        ),
        remediation=(
            "Confirm the third-party destination is expected and covered by "
            "authorization; apply DLP/egress controls and avoid sending secrets "
            "to external services."
        ),
        check=_rule_sensitive_to_external,
    ),
    Rule(
        id="plaintext_credentials",
        version=1,
        title="Plaintext Credential Exposure",
        severity="CRITICAL",
        confidence="OBSERVED",
        description=(
            "Credentials, tokens or session artifacts were observed being "
            "transmitted over a plaintext protocol."
        ),
        remediation=(
            "Enforce TLS (HTTPS) for authentication and session traffic; "
            "rotate any credential observed in cleartext; disable legacy "
            "plaintext management interfaces."
        ),
        check=_rule_plaintext_credentials,
    ),
    Rule(
        id="weak_tls",
        version=1,
        title="Weak TLS Configuration",
        severity="HIGH",
        confidence="OBSERVED",
        description="A TLS session used an obsolete version or a weak cipher suite.",
        remediation=(
            "Disable SSLv3/TLS 1.0/TLS 1.1; prefer TLS 1.2+ with AEAD cipher "
            "suites (AES-GCM or ChaCha20-Poly1305)."
        ),
        check=_rule_weak_tls,
    ),
    Rule(
        id="cleartext_protocols",
        version=1,
        title="Cleartext Management Protocol",
        severity="MEDIUM",
        confidence="OBSERVED",
        description="FTP or Telnet traffic, which transmit credentials in cleartext, was observed.",
        remediation=(
            "Replace FTP with SFTP/FTPS and Telnet with SSH; restrict legacy "
            "protocols at the network boundary."
        ),
        check=_rule_cleartext_protocols,
    ),
    Rule(
        id="session_token_in_url",
        version=1,
        title="Session Token in URL",
        severity="MEDIUM",
        confidence="POSSIBLE",
        description=(
            "URL query parameter names resemble session or token carriers; "
            "values were not inspected."
        ),
        remediation=(
            "Move session/token material into headers or secure cookies; URLs "
            "leak through logs, referrers and browser history."
        ),
        check=_rule_session_token_in_url,
    ),
    Rule(
        id="authorization_in_cleartext",
        version=1,
        title="Authorization Header over Cleartext HTTP",
        severity="HIGH",
        confidence="LIKELY",
        description="An Authorization header was seen on cleartext HTTP.",
        remediation=(
            "Serve authentication endpoints over HTTPS only; reject HTTP "
            "auth attempts and rotate exposed credentials."
        ),
        check=_rule_authorization_in_cleartext,
    ),
    Rule(
        id="unexpected_dns_server",
        version=1,
        title="Unexpected DNS Server",
        severity="MEDIUM",
        confidence="LIKELY",
        description="A non-private DNS server handled queries from internal clients.",
        remediation=(
            "Pin clients to approved resolvers; block outbound UDP/TCP 53 to "
            "unauthorized servers."
        ),
        check=_rule_unexpected_dns_server,
    ),
    Rule(
        id="suspicious_dns",
        version=1,
        title="Suspicious DNS Activity",
        severity="MEDIUM",
        confidence="POSSIBLE",
        description="A client generated a high proportion of failing DNS queries.",
        remediation=(
            "Identify the client process; check for malware with DGA behavior "
            "and verify resolver configuration."
        ),
        check=_rule_suspicious_dns,
    ),
    Rule(
        id="dns_tunneling_indicator",
        version=1,
        title="Possible DNS Tunneling",
        severity="MEDIUM",
        confidence="POSSIBLE",
        description="Unusually long DNS names repeated from one client.",
        remediation=(
            "Inspect the client and the queried domain; consider DNS-layer "
            "filtering and monitoring for tunneling."
        ),
        check=_rule_dns_tunneling_indicator,
    ),
    Rule(
        id="unexpected_external_service",
        version=1,
        title="Remote Administration Service to Public Host",
        severity="HIGH",
        confidence="LIKELY",
        description=(
            "An internal host contacted a public address on a remote "
            "administration port (SSH, RDP, SMB, VNC, Telnet)."
        ),
        remediation=(
            "Restrict outbound administration protocols; require VPN/jump "
            "hosts for external administration."
        ),
        check=_rule_unexpected_external_service,
    ),
    Rule(
        id="port_scan_indicator",
        version=1,
        title="Network Scanning Indicator",
        severity="MEDIUM",
        confidence="POSSIBLE",
        description="Many distinct destination ports were contacted in a short window.",
        remediation=(
            "Identify the scanning host; verify it is an authorized scanner, "
            "otherwise investigate for compromise."
        ),
        check=_rule_port_scan_indicator,
    ),
    Rule(
        id="unusual_traffic_volume",
        version=1,
        title="Unusual Traffic Volume",
        severity="MEDIUM",
        confidence="POSSIBLE",
        description="A host sent far more data than the capture median.",
        remediation=(
            "Review the host's outbound destinations; confirm backup/update "
            "activity is expected."
        ),
        check=_rule_unusual_traffic_volume,
    ),
    Rule(
        id="possible_exfiltration",
        version=1,
        title="Possible Data Exfiltration",
        severity="HIGH",
        confidence="POSSIBLE",
        description="A large internal-to-public transfer was observed.",
        remediation=(
            "Identify the destination and data involved; apply egress "
            "filtering and DLP controls where appropriate."
        ),
        check=_rule_possible_exfiltration,
    ),
    Rule(
        id="possible_tunneling",
        version=1,
        title="Possible Tunneling",
        severity="MEDIUM",
        confidence="POSSIBLE",
        description="VPN/tunnel protocols or DNS-over-TCP were observed.",
        remediation=(
            "Confirm the tunnel is authorized; otherwise block and "
            "investigate the endpoint."
        ),
        check=_rule_possible_tunneling,
    ),
    Rule(
        id="unencrypted_tunnel",
        version=1,
        title="Unencrypted Encapsulation Observed",
        severity="MEDIUM",
        confidence="OBSERVED",
        description=(
            "GRE, IP-in-IP or VXLAN encapsulation was observed; inner traffic "
            "is not protected by the tunnel itself."
        ),
        remediation=(
            "Confirm the encapsulation is authorized and needed; prefer "
            "encrypted tunnels (IPsec/WireGuard) and restrict tunnel endpoints."
        ),
        check=_rule_unencrypted_tunnel,
    ),
    Rule(
        id="authentication_anomaly",
        version=1,
        title="Authentication Anomaly",
        severity="MEDIUM",
        confidence="POSSIBLE",
        description="A burst of HTTP 401/403 responses was observed.",
        remediation=(
            "Check for credential-guessing attempts; enforce lockouts, MFA "
            "and rate limiting."
        ),
        check=_rule_auth_anomaly,
    ),
    Rule(
        id="certificate_validity",
        version=1,
        title="Certificate Expired or Not Yet Valid",
        severity="HIGH",
        confidence="OBSERVED",
        description="A presented certificate was outside its validity window.",
        remediation=(
            "Renew the certificate and verify system clocks; check for "
            "mis-issued certificates."
        ),
        check=_rule_certificate_validity,
    ),
]

RULES_BY_ID = {rule.id: rule for rule in RULES}


def load_overrides(data_dir: Path | None = None) -> dict:
    if data_dir is None:
        return {}
    path = Path(data_dir) / "rules.json"
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    rules = raw.get("rules")
    return rules if isinstance(rules, dict) else {}


def run_rules(
    conn: sqlite3.Connection,
    capture_id: str,
    *,
    data_dir: Path | None = None,
    now: datetime | None = None,
) -> list[dict]:
    overrides = load_overrides(data_dir)
    ctx = RuleContext(
        conn=conn,
        capture_id=capture_id,
        now=now or datetime.now(timezone.utc),
        overrides=overrides,
    )
    results: list[dict] = []
    for rule in RULES:
        rule_override = overrides.get(rule.id) or {}
        if not isinstance(rule_override, dict):
            rule_override = {}
        if not rule.enabled or rule_override.get("enabled") is False:
            continue
        override_severity = str(rule_override.get("severity") or "").upper()
        if override_severity not in SEVERITIES:
            override_severity = ""
        for finding in rule.check(ctx):
            results.append(
                {
                    "rule_id": rule.id,
                    "rule_version": rule.version,
                    "title": rule.title,
                    "description": rule.description,
                    "remediation": rule.remediation,
                    "severity": override_severity
                    or finding.get("severity")
                    or rule.severity,
                    "confidence": finding.get("confidence") or rule.confidence,
                    **{
                        key: finding.get(key)
                        for key in (
                            "explanation",
                            "asset",
                            "src",
                            "dst",
                            "protocol",
                            "first_ts",
                            "last_ts",
                            "evidence_ids",
                            "packet_refs",
                        )
                    },
                    "related": [],
                }
            )
    return results


def run_and_store(
    conn: sqlite3.Connection,
    capture_id: str,
    *,
    data_dir: Path | None = None,
    now: datetime | None = None,
) -> int:
    payloads = run_rules(conn, capture_id, data_dir=data_dir, now=now)
    return findings_store.rebuild(conn, capture_id, payloads)
