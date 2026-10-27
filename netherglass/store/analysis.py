"""M3 network-intelligence storage: hosts, services, DNS/HTTP/TLS events.

Everything here is derived metadata. Payload bytes and secret values never
reach these tables (spec sections 11-13 and the search-index rule in 38).
Correlation is deliberately simple and honest:

- DNS: a response updates the most recent unmatched query with the same
  client/server/qname/qtype. Unmatched responses are stored as orphans.
- HTTP: a response fills status/content-type/server on the most recent
  request of the same TCP stream when possible; both directions are stored.
- TLS: one session row per TCP stream, merged from ClientHello, ServerHello
  and Certificate handshake packets. Certificate SANs arrive from a second
  targeted tshark pass and are merged afterwards.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from . import evidence as evidence_store
from . import findings as findings_store

HOSTNAME_RANK = {
    "dhcp": 1,
    "dns_answer": 2,
    "tls_cert_san": 3,
    "tls_sni": 4,
    "http_host": 5,
    "dns_query": 6,
}

TLS_SERVER_PORTS = {443, 8443, 993, 995, 465, 587, 636, 853, 8883, 5061}


def _rank_sql(column: str) -> str:
    cases = " ".join(
        f"WHEN '{name}' THEN {rank}" for name, rank in HOSTNAME_RANK.items()
    )
    return f"CASE {column} {cases} ELSE 99 END"


def _json_list(items: list[str] | None) -> str | None:
    if not items:
        return None
    return json.dumps(items[:64])


def touch_host(
    conn: sqlite3.Connection,
    capture_id: str,
    ip: str | None,
    *,
    mac: str | None = None,
    ts: float | None = None,
    length: int = 0,
    direction: str = "sent",
    hostname: str | None = None,
    name_source: str | None = None,
) -> None:
    if not ip:
        return
    sent_packets = 1 if direction == "sent" else 0
    recv_packets = 1 - sent_packets
    conn.execute(
        """
        INSERT INTO hosts(capture_id, ip, mac, hostname, hostname_source, first_ts,
                          last_ts, packets, bytes, sent_packets, sent_bytes,
                          recv_packets, recv_bytes)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
        ON CONFLICT(capture_id, ip) DO UPDATE SET
            mac = COALESCE(hosts.mac, excluded.mac),
            hostname = CASE
                WHEN excluded.hostname IS NULL THEN hosts.hostname
                WHEN hosts.hostname IS NULL THEN excluded.hostname
                WHEN {excluded_rank} < {hosts_rank} THEN excluded.hostname
                ELSE hosts.hostname END,
            hostname_source = CASE
                WHEN excluded.hostname IS NULL THEN hosts.hostname_source
                WHEN hosts.hostname IS NULL THEN excluded.hostname_source
                WHEN {excluded_rank} < {hosts_rank} THEN excluded.hostname_source
                ELSE hosts.hostname_source END,
            first_ts = MIN(COALESCE(hosts.first_ts, excluded.first_ts),
                           COALESCE(excluded.first_ts, hosts.first_ts)),
            last_ts = MAX(COALESCE(hosts.last_ts, excluded.last_ts),
                          COALESCE(excluded.last_ts, hosts.last_ts)),
            packets = hosts.packets + 1,
            bytes = hosts.bytes + excluded.bytes,
            sent_packets = hosts.sent_packets + excluded.sent_packets,
            sent_bytes = hosts.sent_bytes + excluded.sent_bytes,
            recv_packets = hosts.recv_packets + excluded.recv_packets,
            recv_bytes = hosts.recv_bytes + excluded.recv_bytes
        """.format(
            excluded_rank=_rank_sql("excluded.hostname_source"),
            hosts_rank=_rank_sql("hosts.hostname_source"),
        ),
        (
            capture_id,
            ip,
            mac,
            hostname,
            name_source,
            ts,
            ts,
            length,
            sent_packets,
            sent_packets * length,
            recv_packets,
            recv_packets * length,
        ),
    )


def add_host_name(
    conn: sqlite3.Connection,
    capture_id: str,
    ip: str | None,
    name: str | None,
    source: str,
    ts: float | None = None,
    *,
    touch: bool = False,
) -> None:
    if not ip or not name:
        return
    conn.execute(
        """
        INSERT INTO host_names(capture_id, ip, name, source, first_ts, last_ts)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(capture_id, ip, name, source) DO UPDATE SET
            first_ts = MIN(COALESCE(host_names.first_ts, excluded.first_ts),
                           COALESCE(excluded.first_ts, host_names.first_ts)),
            last_ts = MAX(COALESCE(host_names.last_ts, excluded.last_ts),
                          COALESCE(excluded.last_ts, host_names.last_ts))
        """,
        (capture_id, ip, name, source, ts, ts),
    )
    if touch:
        ranked = HOSTNAME_RANK.get(source, 99)
        existing = conn.execute(
            "SELECT hostname_source FROM hosts WHERE capture_id = ? AND ip = ?",
            (capture_id, ip),
        ).fetchone()
        current_rank = HOSTNAME_RANK.get(existing["hostname_source"], 99) if existing else 99
        if existing is None or ranked < current_rank:
            if existing is not None:
                conn.execute(
                    "UPDATE hosts SET hostname = ?, hostname_source = ? "
                    "WHERE capture_id = ? AND ip = ?",
                    (name, source, capture_id, ip),
                )


def touch_service(
    conn: sqlite3.Connection,
    capture_id: str,
    ip: str | None,
    port: int | None,
    proto: str | None,
    app_proto: str | None,
    *,
    ts: float | None,
    length: int,
) -> None:
    if not ip or not port:
        return
    conn.execute(
        """
        INSERT INTO services(capture_id, ip, port, proto, app_proto, packets,
                             bytes, first_ts, last_ts)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
        ON CONFLICT(capture_id, ip, port, proto) DO UPDATE SET
            app_proto = COALESCE(services.app_proto, excluded.app_proto),
            packets = services.packets + 1,
            bytes = services.bytes + excluded.bytes,
            first_ts = MIN(COALESCE(services.first_ts, excluded.first_ts),
                           COALESCE(excluded.first_ts, services.first_ts)),
            last_ts = MAX(COALESCE(services.last_ts, excluded.last_ts),
                          COALESCE(excluded.last_ts, services.last_ts))
        """,
        (capture_id, ip, port, (proto or "unknown"), app_proto, length, ts, ts),
    )


def record_dns(conn: sqlite3.Connection, capture_id: str, packet: dict, dns: dict) -> None:
    ts = packet.get("ts")
    src, dst = packet.get("src"), packet.get("dst")
    num = packet.get("num")
    if dns["is_response"]:
        client, server = dst, src
        cursor = conn.execute(
            """
            UPDATE dns_events SET
                rcode = ?, answers = ?, cname_chain = ?, ttl_min = ?,
                matched = 1, response_ts = ?, response_num = ?
            WHERE id = (
                SELECT id FROM dns_events
                WHERE capture_id = ? AND client = ? AND server = ?
                  AND qname = ? AND qtype = ? AND matched = 0
                  AND response_ts IS NULL
                ORDER BY ts DESC LIMIT 1
            )
            """,
            (
                dns["rcode"],
                _json_list(dns["answers"]),
                _json_list(dns["cnames"]),
                dns["ttl_min"],
                ts,
                num,
                capture_id,
                client,
                server,
                dns["qname"],
                dns["qtype"],
            ),
        )
        if cursor.rowcount == 0:
            conn.execute(
                """
                INSERT INTO dns_events(capture_id, ts, client, server, qname, qtype,
                                       rcode, answers, cname_chain, ttl_min, matched,
                                       response_ts, response_num)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2, ?, ?)
                """,
                (
                    capture_id,
                    ts,
                    client,
                    server,
                    dns["qname"],
                    dns["qtype"],
                    dns["rcode"],
                    _json_list(dns["answers"]),
                    _json_list(dns["cnames"]),
                    dns["ttl_min"],
                    ts,
                    num,
                ),
            )
        add_host_name(conn, capture_id, client, dns["qname"], "dns_query", ts, touch=True)
        for answer in dns["answers"]:
            add_host_name(conn, capture_id, answer, dns["qname"], "dns_answer", ts)
    else:
        conn.execute(
            """
            INSERT INTO dns_events(capture_id, ts, client, server, qname, qtype,
                                   rcode, answers, cname_chain, ttl_min, matched)
            VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, 0)
            """,
            (capture_id, ts, src, dst, dns["qname"], dns["qtype"]),
        )
        add_host_name(conn, capture_id, src, dns["qname"], "dns_query", ts, touch=True)


def record_http(conn: sqlite3.Connection, capture_id: str, packet: dict, http: dict) -> None:
    ts = packet.get("ts")
    host = http["host"]
    if http["kind"] == "response":
        match = conn.execute(
            """
            SELECT id, host FROM http_events
            WHERE capture_id = ? AND stream IS ? AND kind = 'request'
              AND status IS NULL AND ts <= ?
            ORDER BY ts DESC LIMIT 1
            """,
            (capture_id, http["stream"], ts),
        ).fetchone()
        if match is not None:
            host = host or match["host"]
            conn.execute(
                """
                UPDATE http_events SET
                    status = ?, content_type = COALESCE(?, content_type),
                    server = COALESCE(?, server)
                WHERE id = ?
                """,
                (
                    http["status"],
                    http["content_type"],
                    http["server"],
                    match["id"],
                ),
            )
    conn.execute(
        """
        INSERT INTO http_events(capture_id, ts, src, dst, sport, dport, stream,
                                kind, method, host, path, query_names, status,
                                user_agent, content_type, server, version,
                                auth_scheme, set_cookie_count, cookie_count, length)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            capture_id,
            ts,
            packet.get("src"),
            packet.get("dst"),
            packet.get("sport"),
            packet.get("dport"),
            http["stream"],
            http["kind"],
            http["method"],
            host,
            http["path"],
            _json_list(http["query_names"]),
            http["status"],
            http["user_agent"],
            http["content_type"],
            http["server"],
            http["version"],
            http["auth_scheme"],
            http["set_cookie_count"],
            http["cookie_count"],
            packet.get("length"),
        ),
    )
    if http["kind"] == "request" and http["host"]:
        add_host_name(conn, capture_id, packet.get("dst"), http["host"], "http_host", ts, touch=True)
    _record_web_security(conn, capture_id, packet, http, host, ts)


COOKIE_KINDS = {
    "SESSION_COOKIE",
    "AUTH_COOKIE",
    "ACCESS_TOKEN",
    "REFRESH_TOKEN",
    "CSRF_TOKEN",
}


def _record_web_security(
    conn: sqlite3.Connection,
    capture_id: str,
    packet: dict,
    http: dict,
    host: str | None,
    ts: float | None,
) -> None:
    plaintext = (packet.get("encryption") or "").lower() == "plaintext"
    headers = http.get("security_headers") or {}
    if http["kind"] == "response" and host:
        conn.execute(
            """
            INSERT INTO web_headers(capture_id, host, responses, hsts, csp,
                                    x_content_type_options, x_frame_options,
                                    referrer_policy, permissions_policy,
                                    cache_control, server, first_ts, last_ts)
            VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(capture_id, host) DO UPDATE SET
                responses = web_headers.responses + 1,
                hsts = web_headers.hsts + excluded.hsts,
                csp = web_headers.csp + excluded.csp,
                x_content_type_options =
                    web_headers.x_content_type_options + excluded.x_content_type_options,
                x_frame_options =
                    web_headers.x_frame_options + excluded.x_frame_options,
                referrer_policy =
                    web_headers.referrer_policy + excluded.referrer_policy,
                permissions_policy =
                    web_headers.permissions_policy + excluded.permissions_policy,
                cache_control = COALESCE(excluded.cache_control, web_headers.cache_control),
                server = COALESCE(excluded.server, web_headers.server),
                first_ts = MIN(COALESCE(web_headers.first_ts, excluded.first_ts),
                               COALESCE(excluded.first_ts, web_headers.first_ts)),
                last_ts = MAX(COALESCE(web_headers.last_ts, excluded.last_ts),
                              COALESCE(excluded.last_ts, web_headers.last_ts))
            """,
            (
                capture_id,
                host,
                int(bool(headers.get("hsts"))),
                int(bool(headers.get("csp"))),
                int(bool(headers.get("x_content_type_options"))),
                int(bool(headers.get("x_frame_options"))),
                int(bool(headers.get("referrer_policy"))),
                int(bool(headers.get("permissions_policy"))),
                headers.get("cache_control"),
                headers.get("server"),
                ts,
                ts,
            ),
        )
    set_cookies = http.get("set_cookies") or []
    for cookie in set_cookies:
        _upsert_cookie(
            conn,
            capture_id,
            cookie["name"],
            host or "",
            cookie,
            plaintext=plaintext,
            ts=ts,
        )
    request_names = http.get("request_cookie_names") or []
    for name in request_names:
        _upsert_cookie(
            conn,
            capture_id,
            name,
            host or "",
            None,
            plaintext=plaintext,
            ts=ts,
        )


def _cookie_kind(name: str) -> str:
    lowered = name.lower()
    if "csrf" in lowered or "xsrf" in lowered:
        return "CSRF_TOKEN"
    if "refresh" in lowered:
        return "REFRESH_TOKEN"
    if "session" in lowered or lowered in ("sid", "sess", "phpsessid", "jsessionid"):
        return "SESSION_COOKIE"
    if "auth" in lowered or "sso" in lowered or "login" in lowered:
        return "AUTH_COOKIE"
    if any(marker in lowered for marker in ("token", "bearer", "access")):
        return "ACCESS_TOKEN"
    return "OTHER"


def _upsert_cookie(
    conn: sqlite3.Connection,
    capture_id: str,
    name: str,
    host: str,
    attributes: dict | None,
    *,
    plaintext: bool,
    ts: float | None,
) -> None:
    attrs = attributes or {}
    kind = _cookie_kind(name)
    if kind not in COOKIE_KINDS:
        kind = "OTHER"
    conn.execute(
        """
        INSERT INTO web_cookies(capture_id, name, host, kind, set_observed, secure,
                                http_only, same_site, domain, path, max_age, plaintext,
                                seen_count, first_ts, last_ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        ON CONFLICT(capture_id, name, host) DO UPDATE SET
            kind = CASE WHEN web_cookies.kind = 'OTHER' THEN excluded.kind
                        ELSE web_cookies.kind END,
            set_observed = MAX(web_cookies.set_observed, excluded.set_observed),
            secure = MAX(web_cookies.secure, excluded.secure),
            http_only = MAX(web_cookies.http_only, excluded.http_only),
            same_site = COALESCE(web_cookies.same_site, excluded.same_site),
            domain = COALESCE(web_cookies.domain, excluded.domain),
            path = COALESCE(web_cookies.path, excluded.path),
            max_age = COALESCE(web_cookies.max_age, excluded.max_age),
            plaintext = MAX(web_cookies.plaintext, excluded.plaintext),
            seen_count = web_cookies.seen_count + 1,
            first_ts = MIN(COALESCE(web_cookies.first_ts, excluded.first_ts),
                           COALESCE(excluded.first_ts, web_cookies.first_ts)),
            last_ts = MAX(COALESCE(web_cookies.last_ts, excluded.last_ts),
                          COALESCE(excluded.last_ts, web_cookies.last_ts))
        """,
        (
            capture_id,
            name,
            host,
            kind,
            int(attributes is not None),
            int(bool(attrs.get("secure"))),
            int(bool(attrs.get("http_only"))),
            attrs.get("same_site"),
            attrs.get("domain"),
            attrs.get("path"),
            attrs.get("max_age"),
            int(plaintext),
            ts,
            ts,
        ),
    )


def record_tunnel(
    conn: sqlite3.Connection, capture_id: str, packet: dict, tunnel: dict
) -> None:
    protocol = tunnel.get("protocol")
    src, dst = packet.get("src"), packet.get("dst")
    if not protocol or not src or not dst:
        return
    ts = packet.get("ts")
    length = packet.get("length") or 0
    conn.execute(
        """
        INSERT INTO tunnels(capture_id, tunnel_proto, src, dst, sport, dport,
                            state, inner_visible, packets, bytes, first_ts, last_ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
        ON CONFLICT(capture_id, tunnel_proto, src, dst, sport, dport) DO UPDATE SET
            packets = tunnels.packets + 1,
            bytes = tunnels.bytes + excluded.bytes,
            state = CASE
                WHEN tunnels.state = 'HANDSHAKE' THEN tunnels.state
                WHEN excluded.state = 'HANDSHAKE' THEN excluded.state
                ELSE tunnels.state END,
            inner_visible = MAX(tunnels.inner_visible, excluded.inner_visible),
            first_ts = MIN(COALESCE(tunnels.first_ts, excluded.first_ts),
                           excluded.first_ts),
            last_ts = MAX(COALESCE(tunnels.last_ts, excluded.last_ts),
                          excluded.last_ts)
        """,
        (
            capture_id,
            protocol,
            src,
            dst,
            packet.get("sport") or 0,
            packet.get("dport") or 0,
            tunnel.get("state") or "OBSERVED",
            int(tunnel.get("inner_visible") or 0),
            length,
            ts,
            ts,
        ),
    )


def record_tls(conn: sqlite3.Connection, capture_id: str, packet: dict, tls: dict) -> None:
    stream = tls.get("stream")
    if stream is None:
        return
    src, dst = packet.get("src"), packet.get("dst")
    sport, dport = packet.get("sport"), packet.get("dport")
    server = client = None
    if sport in TLS_SERVER_PORTS and dport not in TLS_SERVER_PORTS:
        server, client = src, dst
    elif dport in TLS_SERVER_PORTS:
        server, client = dst, src
    elif tls["kind"] == "client_hello":
        client, server = src, dst
    else:
        client, server = dst, src
    ts = packet.get("ts")
    conn.execute(
        """
        INSERT INTO tls_sessions(capture_id, stream, client, server, sport, dport,
                                 version, sni, alpn, cipher, ja3, ja4, cert_count,
                                 cert_not_before, cert_not_after, security,
                                 first_ts, last_ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(capture_id, stream) DO UPDATE SET
            version = COALESCE(excluded.version, tls_sessions.version),
            sni = COALESCE(excluded.sni, tls_sessions.sni),
            alpn = COALESCE(excluded.alpn, tls_sessions.alpn),
            cipher = COALESCE(excluded.cipher, tls_sessions.cipher),
            ja3 = COALESCE(excluded.ja3, tls_sessions.ja3),
            ja4 = COALESCE(excluded.ja4, tls_sessions.ja4),
            cert_count = COALESCE(excluded.cert_count, tls_sessions.cert_count),
            cert_not_before = COALESCE(excluded.cert_not_before, tls_sessions.cert_not_before),
            cert_not_after = COALESCE(excluded.cert_not_after, tls_sessions.cert_not_after),
            security = COALESCE(excluded.security, tls_sessions.security),
            first_ts = MIN(COALESCE(tls_sessions.first_ts, excluded.first_ts),
                           COALESCE(excluded.first_ts, tls_sessions.first_ts)),
            last_ts = MAX(COALESCE(tls_sessions.last_ts, excluded.last_ts),
                          COALESCE(excluded.last_ts, tls_sessions.last_ts))
        """,
        (
            capture_id,
            stream,
            client,
            server,
            sport if client == src else dport,
            dport if client == src else sport,
            tls["version"],
            tls["sni"],
            tls["alpn"],
            tls["cipher"],
            tls["ja3"],
            tls["ja4"],
            tls["cert_count"],
            tls["cert_not_before"],
            tls["cert_not_after"],
            tls.get("security"),
            ts,
            ts,
        ),
    )
    add_host_name(conn, capture_id, server, tls["sni"], "tls_sni", ts, touch=True)


def apply_tls_certificates(
    conn: sqlite3.Connection, capture_id: str, records: list[dict]
) -> int:
    applied = 0
    for record in records:
        stream = record.get("stream")
        if not stream:
            continue
        conn.execute(
            "INSERT OR IGNORE INTO tls_sessions(capture_id, stream) VALUES (?, ?)",
            (capture_id, stream),
        )
        cursor = conn.execute(
            "UPDATE tls_sessions SET cert_sans = COALESCE(cert_sans, ?), "
            "cert_name_strings = COALESCE(cert_name_strings, ?) "
            "WHERE capture_id = ? AND stream = ?",
            (
                _json_list(record.get("sans")),
                _json_list(record.get("name_strings")),
                capture_id,
                stream,
            ),
        )
        if cursor.rowcount:
            applied += 1
        row = conn.execute(
            "SELECT server FROM tls_sessions WHERE capture_id = ? AND stream = ?",
            (capture_id, stream),
        ).fetchone()
        if row:
            for san in (record.get("sans") or [])[:32]:
                add_host_name(conn, capture_id, row["server"], san, "tls_cert_san")
    return applied


def record_batch(conn: sqlite3.Connection, capture_id: str, rows: list[dict]) -> None:
    for packet in rows:
        ts = packet.get("ts")
        length = packet.get("length") or 0
        touch_host(
            conn,
            capture_id,
            packet.get("src"),
            mac=packet.get("src_mac"),
            ts=ts,
            length=length,
            direction="sent",
        )
        touch_host(
            conn,
            capture_id,
            packet.get("dst"),
            mac=packet.get("dst_mac"),
            ts=ts,
            length=length,
            direction="received",
        )
        touch_service(
            conn,
            capture_id,
            packet.get("dst"),
            packet.get("dport"),
            packet.get("proto"),
            packet.get("app_proto"),
            ts=ts,
            length=length,
        )
        if packet.get("dns"):
            record_dns(conn, capture_id, packet, packet["dns"])
        if packet.get("http"):
            record_http(conn, capture_id, packet, packet["http"])
        if packet.get("tls"):
            record_tls(conn, capture_id, packet, packet["tls"])
        if packet.get("tunnel"):
            record_tunnel(conn, capture_id, packet, packet["tunnel"])


# ---------------------------------------------------------------- listing


def list_tunnels(conn: sqlite3.Connection, capture_id: str) -> list[dict]:
    rows = conn.execute(
        """
        SELECT capture_id, tunnel_proto, src, dst, sport, dport, state,
               inner_visible, packets, bytes, first_ts, last_ts
        FROM tunnels WHERE capture_id = ?
        ORDER BY bytes DESC, tunnel_proto LIMIT 500
        """,
        (capture_id,),
    ).fetchall()
    tunnels = []
    for row in rows:
        item = dict(row)
        first, last = item.get("first_ts"), item.get("last_ts")
        item["duration"] = (
            round(last - first, 3) if first is not None and last is not None else None
        )
        tunnels.append(item)
    return tunnels


def list_hosts(conn: sqlite3.Connection, capture_id: str, *, limit: int = 200) -> list[dict]:
    rows = conn.execute(
        """
        SELECT capture_id, ip, mac, hostname, hostname_source, first_ts, last_ts,
               packets, bytes, sent_packets, sent_bytes, recv_packets, recv_bytes
        FROM hosts WHERE capture_id = ?
        ORDER BY bytes DESC, ip LIMIT ?
        """,
        (capture_id, limit),
    ).fetchall()
    return [dict(row) for row in rows]


def get_host(conn: sqlite3.Connection, capture_id: str, ip: str) -> dict | None:
    host = conn.execute(
        "SELECT * FROM hosts WHERE capture_id = ? AND ip = ?", (capture_id, ip)
    ).fetchone()
    if host is None:
        return None
    names = conn.execute(
        "SELECT name, source, first_ts, last_ts FROM host_names "
        "WHERE capture_id = ? AND ip = ? ORDER BY source, name LIMIT 200",
        (capture_id, ip),
    ).fetchall()
    services = conn.execute(
        "SELECT port, proto, app_proto, packets, bytes, first_ts, last_ts FROM services "
        "WHERE capture_id = ? AND ip = ? ORDER BY packets DESC LIMIT 100",
        (capture_id, ip),
    ).fetchall()
    flows = conn.execute(
        "SELECT src, dst, proto, dport, packets, bytes, first_ts, last_ts FROM flows "
        "WHERE capture_id = ? AND (src = ? OR dst = ?) ORDER BY bytes DESC LIMIT 100",
        (capture_id, ip, ip),
    ).fetchall()
    dns = conn.execute(
        "SELECT ts, client, server, qname, qtype, rcode, answers, matched, response_ts "
        "FROM dns_events WHERE capture_id = ? AND (client = ? OR server = ? OR "
        "answers LIKE ?) ORDER BY ts DESC LIMIT 50",
        (capture_id, ip, ip, f'%"{ip}"%'),
    ).fetchall()
    http = conn.execute(
        "SELECT ts, kind, method, host, path, status, content_type, server FROM http_events "
        "WHERE capture_id = ? AND (src = ? OR dst = ?) ORDER BY ts DESC LIMIT 50",
        (capture_id, ip, ip),
    ).fetchall()
    tls = conn.execute(
        "SELECT stream, client, server, version, sni, alpn, cipher, cert_not_before, "
        "cert_not_after, cert_sans FROM tls_sessions "
        "WHERE capture_id = ? AND (client = ? OR server = ?) ORDER BY first_ts DESC LIMIT 50",
        (capture_id, ip, ip),
    ).fetchall()
    return {
        "host": dict(host),
        "names": [dict(row) for row in names],
        "services": [dict(row) for row in services],
        "flows": [dict(row) for row in flows],
        "dns": [dict(row) for row in dns],
        "http": [dict(row) for row in http],
        "tls": [dict(row) for row in tls],
    }


def list_dns(
    conn: sqlite3.Connection,
    capture_id: str,
    *,
    limit: int = 200,
    offset: int = 0,
    qname: str | None = None,
    rcode: str | None = None,
    qtype: str | None = None,
) -> dict:
    where = ["capture_id = ?"]
    params: list[Any] = [capture_id]
    if qname:
        where.append("LOWER(qname) LIKE LOWER(?)")
        params.append(f"%{qname}%")
    if rcode:
        where.append("rcode = ?")
        params.append(rcode.upper())
    if qtype:
        where.append("qtype = ?")
        params.append(qtype.upper())
    clause = " AND ".join(where)
    total = conn.execute(
        f"SELECT COUNT(*) AS n FROM dns_events WHERE {clause}", params
    ).fetchone()["n"]
    rows = conn.execute(
        "SELECT id, ts, client, server, qname, qtype, rcode, answers, cname_chain, "
        f"ttl_min, matched, response_ts FROM dns_events WHERE {clause} "
        "ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()
    return {"total": total, "limit": limit, "offset": offset,
            "events": [dict(row) for row in rows]}


def list_http(
    conn: sqlite3.Connection,
    capture_id: str,
    *,
    limit: int = 200,
    offset: int = 0,
    host: str | None = None,
    method: str | None = None,
    status: int | None = None,
    kind: str | None = None,
) -> dict:
    where = ["capture_id = ?"]
    params: list[Any] = [capture_id]
    if host:
        where.append("LOWER(host) LIKE LOWER(?)")
        params.append(f"%{host}%")
    if method:
        where.append("UPPER(method) = ?")
        params.append(method.upper())
    if status:
        where.append("status = ?")
        params.append(status)
    if kind in ("request", "response"):
        where.append("kind = ?")
        params.append(kind)
    clause = " AND ".join(where)
    total = conn.execute(
        f"SELECT COUNT(*) AS n FROM http_events WHERE {clause}", params
    ).fetchone()["n"]
    rows = conn.execute(
        "SELECT id, ts, src, dst, sport, dport, stream, kind, method, host, path, "
        "query_names, status, user_agent, content_type, server, version, auth_scheme, "
        f"set_cookie_count, cookie_count, length FROM http_events WHERE {clause} "
        "ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()
    return {"total": total, "limit": limit, "offset": offset,
            "events": [dict(row) for row in rows]}


def list_tls(
    conn: sqlite3.Connection,
    capture_id: str,
    *,
    limit: int = 200,
    offset: int = 0,
    sni: str | None = None,
    version: str | None = None,
) -> dict:
    where = ["capture_id = ?"]
    params: list[Any] = [capture_id]
    if sni:
        where.append("LOWER(sni) LIKE LOWER(?)")
        params.append(f"%{sni}%")
    if version:
        where.append("version = ?")
        params.append(version)
    clause = " AND ".join(where)
    total = conn.execute(
        f"SELECT COUNT(*) AS n FROM tls_sessions WHERE {clause}", params
    ).fetchone()["n"]
    rows = conn.execute(
        "SELECT stream, client, server, sport, dport, version, sni, alpn, cipher, "
        "ja3, ja4, cert_count, cert_not_before, cert_not_after, cert_sans, "
        f"security, first_ts, last_ts FROM tls_sessions WHERE {clause} "
        "ORDER BY first_ts DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()
    return {"total": total, "limit": limit, "offset": offset,
            "sessions": [dict(row) for row in rows]}


# --------------------------------------------------------------- statistics

_TOP = 15


def _bucket_rows(conn: sqlite3.Connection, capture_id: str, sql: str) -> list[dict]:
    return [dict(row) for row in conn.execute(sql, (capture_id,)).fetchall()]


def stats(conn: sqlite3.Connection, capture_id: str) -> dict:
    top_talkers = _bucket_rows(
        conn,
        capture_id,
        "SELECT ip, hostname, packets, bytes, sent_bytes, recv_bytes FROM hosts "
        f"WHERE capture_id = ? ORDER BY bytes DESC LIMIT {_TOP}",
    )
    top_destinations = _bucket_rows(
        conn,
        capture_id,
        "SELECT dst AS ip, COUNT(*) AS packets, COALESCE(SUM(length), 0) AS bytes "
        f"FROM packets WHERE capture_id = ? AND dst IS NOT NULL GROUP BY dst "
        f"ORDER BY bytes DESC LIMIT {_TOP}",
    )
    top_domains = _bucket_rows(
        conn,
        capture_id,
        "SELECT qname, COUNT(*) AS queries, "
        "SUM(CASE WHEN rcode = 'NXDOMAIN' THEN 1 ELSE 0 END) AS nxdomain "
        "FROM dns_events WHERE capture_id = ? AND matched IN (0, 1) "
        f"GROUP BY qname ORDER BY queries DESC LIMIT {_TOP}",
    )
    top_ports = _bucket_rows(
        conn,
        capture_id,
        "SELECT dport AS port, COALESCE(app_proto, proto) AS proto, COUNT(*) AS packets, "
        "COALESCE(SUM(length), 0) AS bytes FROM packets "
        f"WHERE capture_id = ? AND dport IS NOT NULL AND dport > 0 GROUP BY dport "
        f"ORDER BY packets DESC LIMIT {_TOP}",
    )
    top_protocols = _bucket_rows(
        conn,
        capture_id,
        "SELECT COALESCE(app_proto, proto) AS protocol, COUNT(*) AS packets, "
        "COALESCE(SUM(length), 0) AS bytes FROM packets WHERE capture_id = ? "
        f"GROUP BY protocol ORDER BY packets DESC LIMIT {_TOP}",
    )
    traffic_over_time = _bucket_rows(
        conn,
        capture_id,
        "SELECT CAST(ts / 60 AS INTEGER) AS bucket, COUNT(*) AS packets, "
        "COALESCE(SUM(length), 0) AS bytes FROM packets "
        "WHERE capture_id = ? AND ts IS NOT NULL GROUP BY bucket "
        "ORDER BY bucket DESC LIMIT 120",
    )
    traffic_over_time.reverse()
    dns_volume = _bucket_rows(
        conn,
        capture_id,
        "SELECT CAST(ts / 60 AS INTEGER) AS bucket, COUNT(*) AS queries, "
        "SUM(CASE WHEN rcode = 'NXDOMAIN' THEN 1 ELSE 0 END) AS nxdomain "
        "FROM dns_events WHERE capture_id = ? AND matched IN (0, 1) "
        "GROUP BY bucket ORDER BY bucket DESC LIMIT 120",
    )
    dns_volume.reverse()
    tls_versions = _bucket_rows(
        conn,
        capture_id,
        "SELECT COALESCE(version, 'unknown') AS version, COUNT(*) AS sessions "
        "FROM tls_sessions WHERE capture_id = ? GROUP BY version ORDER BY sessions DESC",
    )
    encryption = _bucket_rows(
        conn,
        capture_id,
        "SELECT encryption, COUNT(*) AS packets, COALESCE(SUM(length), 0) AS bytes "
        "FROM packets WHERE capture_id = ? GROUP BY encryption",
    )
    security = _bucket_rows(
        conn,
        capture_id,
        "SELECT security, COUNT(*) AS packets, COALESCE(SUM(length), 0) AS bytes "
        "FROM packets WHERE capture_id = ? GROUP BY security",
    )
    dns_summary = _bucket_rows(
        conn,
        capture_id,
        "SELECT COUNT(*) AS queries, "
        "SUM(CASE WHEN rcode = 'NXDOMAIN' THEN 1 ELSE 0 END) AS nxdomain, "
        "SUM(CASE WHEN matched = 2 THEN 1 ELSE 0 END) AS orphan_responses "
        "FROM dns_events WHERE capture_id = ? AND matched IN (0, 1, 2)",
    )
    return {
        "top_talkers": top_talkers,
        "top_destinations": top_destinations,
        "top_domains": top_domains,
        "top_ports": top_ports,
        "top_protocols": top_protocols,
        "traffic_over_time": traffic_over_time,
        "dns_volume": dns_volume,
        "dns_summary": dns_summary[0] if dns_summary else {},
        "tls_versions": tls_versions,
        "encryption": encryption,
        "security": security,
        "findings": findings_store.summary(conn, capture_id),
        "sensitive_data": {
            "available": True,
            "by_type": evidence_store.summary(conn, capture_id),
        },
    }
