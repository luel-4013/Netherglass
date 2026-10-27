"""Network and connection graph (spec section 41).

Nodes are hosts (IP, hostname, MAC), external domains and findings; edges are
flows, DNS resolutions, TLS sessions, HTTP requests and finding attachments.
Bounded node/edge counts keep the response usable for large captures.
"""

from __future__ import annotations

import ipaddress
import sqlite3

MAX_HOSTS = 300
MAX_EDGES = 1200


def _private(ip: str | None) -> bool | None:
    if not ip:
        return None
    try:
        address = ipaddress.ip_address(str(ip))
    except ValueError:
        return None
    return address.is_private or address.is_loopback or address.is_link_local


def network_graph(conn: sqlite3.Connection, capture_id: str) -> dict:
    hosts = conn.execute(
        "SELECT ip, mac, hostname, hostname_source, packets, bytes, sent_bytes, "
        "recv_bytes FROM hosts WHERE capture_id = ? ORDER BY bytes DESC LIMIT ?",
        (capture_id, MAX_HOSTS),
    ).fetchall()
    nodes = []
    known = set()
    for row in hosts:
        known.add(row["ip"])
        internal = _private(row["ip"])
        nodes.append(
            {
                "id": row["ip"],
                "label": row["hostname"] or row["ip"],
                "kind": "host",
                "internal": internal,
                "mac": row["mac"],
                "hostname_source": row["hostname_source"],
                "packets": row["packets"],
                "bytes": row["bytes"],
            }
        )
    edges = []
    seen = set()
    for row in conn.execute(
        "SELECT src, dst, proto, dport, packets, bytes FROM flows "
        "WHERE capture_id = ? ORDER BY bytes DESC LIMIT ?",
        (capture_id, MAX_EDGES),
    ):
        key = (row["src"], row["dst"], row["proto"], row["dport"])
        if key in seen:
            continue
        seen.add(key)
        edges.append(
            {
                "source": row["src"],
                "target": row["dst"],
                "kind": "flow",
                "proto": row["proto"],
                "dport": row["dport"],
                "packets": row["packets"],
                "bytes": row["bytes"],
            }
        )
    return {"nodes": nodes, "edges": edges, "truncated": len(hosts) >= MAX_HOSTS}


def connection_graph(conn: sqlite3.Connection, capture_id: str) -> dict:
    """Host -> DNS -> domain -> IP -> TLS -> certificate -> HTTP -> finding."""
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    edge_keys: set[tuple] = set()

    def node(node_id: str, label: str, kind: str, **extra) -> str:
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "label": label, "kind": kind, **extra}
        return node_id

    def edge(source: str, target: str, kind: str, **extra) -> None:
        key = (source, target, kind)
        if key in edge_keys:
            return
        edge_keys.add(key)
        if len(edges) < MAX_EDGES:
            edges.append({"source": source, "target": target, "kind": kind, **extra})

    for row in conn.execute(
        "SELECT client, qname FROM dns_events WHERE capture_id = ? "
        "AND matched IN (0, 1) ORDER BY ts LIMIT ?",
        (capture_id, MAX_EDGES),
    ):
        if not row["client"] or not row["qname"]:
            continue
        host = node(f"ip:{row['client']}", row["client"], "host")
        domain = node(f"domain:{row['qname']}", row["qname"], "domain")
        edge(host, domain, "dns")

    for row in conn.execute(
        "SELECT sni, server, version, security, cert_sans FROM tls_sessions "
        "WHERE capture_id = ? AND sni IS NOT NULL LIMIT ?",
        (capture_id, MAX_HOSTS),
    ):
        domain = node(f"domain:{row['sni']}", row["sni"], "domain")
        if row["server"]:
            ip = node(f"ip:{row['server']}", row["server"], "host")
            edge(domain, ip, "resolves")
        cert = node(
            f"tls:{row['sni']}",
            f"TLS {row['version'] or '?'}",
            "tls",
            security=row["security"],
        )
        edge(domain, cert, "tls", version=row["version"])
        if row["cert_sans"]:
            edge(cert, domain, "certificate")

    for row in conn.execute(
        "SELECT host, dst, method, path FROM http_events WHERE capture_id = ? "
        "AND kind = 'request' AND host IS NOT NULL LIMIT ?",
        (capture_id, MAX_EDGES),
    ):
        domain = node(f"domain:{row['host']}", row["host"], "domain")
        if row["dst"]:
            ip = node(f"ip:{row['dst']}", row["dst"], "host")
            edge(domain, ip, "resolves")
        endpoint = node(
            f"http:{row['host']}{row['path'] or '/'}",
            f"{row['method'] or '?'} {row['path'] or '/'}",
            "http",
        )
        edge(domain, endpoint, "http")

    for row in conn.execute(
        "SELECT id, asset, title, severity FROM findings WHERE capture_id = ? "
        "ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
        "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END LIMIT 200",
        (capture_id,),
    ):
        finding = node(
            f"finding:{row['id']}",
            f"{row['severity']} {row['title']}",
            "finding",
            severity=row["severity"],
        )
        if row["asset"]:
            asset = f"ip:{row['asset']}" if _private(row["asset"]) is not None else f"domain:{row['asset']}"
            node(asset, row["asset"], "host")
            edge(asset, finding, "finding")

    return {"nodes": list(nodes.values()), "edges": edges}
