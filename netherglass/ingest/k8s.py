"""Kubernetes inventory adapter (spec section 43).

Accepts raw ``kubectl get <kind> -o json`` outputs, normalizes nodes, pods,
services and namespaces into ``k8s_entities`` and correlates pod IPs with
observed flows: Pod -> Service -> Pod IP -> Node -> Destination.

Honesty rule: correlation only states what the inventory and observed flows
show; a pod IP may be reused, so confidence stays observational.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from ..security.audit import append_event
from ..store.db import Database

_MAX_ITEMS = 50_000


class K8sError(ValueError):
    """Invalid Kubernetes inventory input."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _items(value) -> list[dict]:
    if value is None:
        return []
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)][:_MAX_ITEMS]
    if isinstance(value, dict):
        items = value.get("items")
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)][:_MAX_ITEMS]
        return [value]
    raise K8sError("inventory sections must be kubectl JSON objects or lists")


def _labels(meta: dict) -> str | None:
    labels = meta.get("labels")
    if not isinstance(labels, dict) or not labels:
        return None
    return json.dumps(
        {str(k)[:128]: str(v)[:256] for k, v in list(labels.items())[:64]},
        sort_keys=True,
    )


def normalize_inventory(payload: dict) -> list[dict]:
    if not isinstance(payload, dict):
        raise K8sError("inventory payload must be a JSON object")
    sections = {
        key: _items(payload.get(key))
        for key in ("nodes", "pods", "services", "namespaces")
    }
    if not any(sections.values()):
        raise K8sError(
            "inventory is empty; provide at least one of: nodes, pods, services, "
            "namespaces"
        )
    entities: list[dict] = []

    for ns in sections["namespaces"]:
        meta = ns.get("metadata") or {}
        name = str(meta.get("name") or "").strip()
        if name:
            entities.append(
                {"kind": "namespace", "namespace": "", "name": name[:253]}
            )

    for node in sections["nodes"]:
        meta = node.get("metadata") or {}
        name = str(meta.get("name") or "").strip()
        if not name:
            continue
        ip = None
        for address in (node.get("status") or {}).get("addresses") or []:
            if str(address.get("type")) in ("InternalIP", "ExternalIP"):
                ip = str(address.get("address") or "").strip() or None
                if address.get("type") == "InternalIP":
                    break
        entities.append(
            {
                "kind": "node",
                "namespace": "",
                "name": name[:253],
                "ip": ip,
                "labels": _labels(meta),
            }
        )

    for pod in sections["pods"]:
        meta = pod.get("metadata") or {}
        spec = pod.get("spec") or {}
        status = pod.get("status") or {}
        name = str(meta.get("name") or "").strip()
        if not name:
            continue
        ports = []
        for container in spec.get("containers") or []:
            for port in container.get("ports") or []:
                value = port.get("containerPort")
                if value:
                    ports.append(int(value))
        entities.append(
            {
                "kind": "pod",
                "namespace": str(meta.get("namespace") or "default")[:253],
                "name": name[:253],
                "node": str(spec.get("nodeName") or "")[:253] or None,
                "ip": str(status.get("podIP") or "").strip() or None,
                "labels": _labels(meta),
                "ports": json.dumps(sorted(set(ports)), sort_keys=True)
                if ports
                else None,
            }
        )

    for service in sections["services"]:
        meta = service.get("metadata") or {}
        spec = service.get("spec") or {}
        name = str(meta.get("name") or "").strip()
        if not name:
            continue
        selector = spec.get("selector")
        labels = meta.get("labels")
        merged: dict[str, str] = {}
        if isinstance(labels, dict):
            merged.update({str(k): str(v) for k, v in labels.items()})
        if isinstance(selector, dict) and selector:
            merged["__selector"] = json.dumps(
                {str(k): str(v) for k, v in selector.items()}, sort_keys=True
            )
        ports = [
            int(port["port"])
            for port in spec.get("ports") or []
            if isinstance(port.get("port"), int)
        ]
        entities.append(
            {
                "kind": "service",
                "namespace": str(meta.get("namespace") or "default")[:253],
                "name": name[:253],
                "ip": str(spec.get("clusterIP") or "").strip() or None,
                "labels": json.dumps(merged, sort_keys=True)[:4096]
                if merged
                else None,
                "ports": json.dumps(sorted(set(ports)), sort_keys=True)
                if ports
                else None,
            }
        )
    return entities


def import_inventory(
    db: Database, payload: dict, *, actor: str, label: str | None = None
) -> dict:
    entities = normalize_inventory(payload)
    counts = {"node": 0, "pod": 0, "service": 0, "namespace": 0}
    ts = datetime.now(timezone.utc).timestamp()
    with db.connect() as conn:
        for entity in entities:
            counts[entity["kind"]] += 1
            conn.execute(
                """
                INSERT INTO k8s_entities(kind, namespace, name, node, ip, labels,
                                         ports, first_ts, last_ts)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(kind, namespace, name) DO UPDATE SET
                    node = COALESCE(excluded.node, k8s_entities.node),
                    ip = COALESCE(excluded.ip, k8s_entities.ip),
                    labels = COALESCE(excluded.labels, k8s_entities.labels),
                    ports = COALESCE(excluded.ports, k8s_entities.ports),
                    last_ts = excluded.last_ts
                """,
                (
                    entity["kind"],
                    entity.get("namespace") or "",
                    entity["name"],
                    entity.get("node"),
                    entity.get("ip"),
                    entity.get("labels"),
                    entity.get("ports"),
                    ts,
                    ts,
                ),
            )
        append_event(
            conn,
            actor=actor,
            action="K8S_IMPORTED",
            target=label or "cluster",
            details={**counts, "label": label},
        )
    return {"entities": len(entities), **counts}


def list_entities(
    conn,
    *,
    kind: str | None = None,
    namespace: str | None = None,
    limit: int = 500,
) -> list[dict]:
    where, params = [], []
    if kind:
        where.append("kind = ?")
        params.append(kind)
    if namespace:
        where.append("namespace = ?")
        params.append(namespace)
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    rows = conn.execute(
        f"""
        SELECT id, kind, namespace, name, node, ip, labels, ports, first_ts, last_ts
        FROM k8s_entities {clause}
        ORDER BY kind, namespace, name LIMIT ?
        """,
        params + [limit],
    ).fetchall()
    return [dict(row) for row in rows]


def _load_pods(conn) -> dict[str, dict]:
    rows = conn.execute(
        """
        SELECT kind, namespace, name, node, ip, labels, ports
        FROM k8s_entities WHERE kind = 'pod' AND ip IS NOT NULL
        """
    ).fetchall()
    pods: dict[str, dict] = {}
    for row in rows:
        pods[row["ip"]] = dict(row)
    return pods


def _load_services(conn) -> dict[str, list[dict]]:
    rows = conn.execute(
        """
        SELECT kind, namespace, name, ip, labels, ports
        FROM k8s_entities WHERE kind = 'service'
        """
    ).fetchall()
    by_ns: dict[str, list[dict]] = {}
    for row in rows:
        entity = dict(row)
        selector = None
        if entity.get("labels"):
            try:
                parsed = json.loads(entity["labels"])
                selector = parsed.pop("__selector", None)
                if selector:
                    selector = json.loads(selector)
                entity["labels"] = json.dumps(parsed, sort_keys=True) if parsed else None
            except (json.JSONDecodeError, TypeError):
                selector = None
        entity["selector"] = selector
        by_ns.setdefault(entity["namespace"], []).append(entity)
    return by_ns


def _services_for_pod(pod: dict, services_by_ns: dict[str, list[dict]]) -> list[dict]:
    if not pod:
        return []
    matches = []
    pod_labels = {}
    if pod.get("labels"):
        try:
            pod_labels = json.loads(pod["labels"])
        except (json.JSONDecodeError, TypeError):
            pod_labels = {}
    for service in services_by_ns.get(pod.get("namespace") or "", []):
        selector = service.get("selector") or {}
        if selector and all(pod_labels.get(k) == v for k, v in selector.items()):
            matches.append(
                {"name": service["name"], "namespace": service["namespace"]}
            )
    return matches


def correlate_capture(conn, capture_id: str, *, limit: int = 200) -> dict:
    pods = _load_pods(conn)
    services_by_ns = _load_services(conn)
    rows = conn.execute(
        """
        SELECT src, dst, proto, dport, packets, bytes, first_ts, last_ts
        FROM flows WHERE capture_id = ?
        ORDER BY bytes DESC LIMIT ?
        """,
        (capture_id, limit),
    ).fetchall()

    flows: list[dict] = []
    matched = 0
    for row in rows:
        flow = dict(row)
        src_pod = pods.get(flow["src"])
        dst_pod = pods.get(flow["dst"])
        flow["src_pod"] = (
            {
                "name": src_pod["name"],
                "namespace": src_pod["namespace"],
                "node": src_pod["node"],
            }
            if src_pod
            else None
        )
        flow["dst_pod"] = (
            {
                "name": dst_pod["name"],
                "namespace": dst_pod["namespace"],
                "node": dst_pod["node"],
            }
            if dst_pod
            else None
        )
        flow["dst_services"] = _services_for_pod(dst_pod, services_by_ns) if dst_pod else []
        flow["src_services"] = _services_for_pod(src_pod, services_by_ns) if src_pod else []
        if src_pod or dst_pod:
            matched += 1
        flows.append(flow)
    return {
        "capture_id": capture_id,
        "pods_known": len(pods),
        "flows": flows,
        "matched": matched,
        "total": len(rows),
    }
