"""M3 analysis endpoints: hosts, DNS, HTTP, TLS, search and statistics."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ..analysis.query import DEFERRED_FIELDS, FIELDS, QueryError, compile_query
from ..security.rbac import Permission, has_permission
from ..store import analysis as analysis_store
from ..store import packets as packets_store
from .deps import require_permission

router = APIRouter(prefix="/api", tags=["analysis"])

_META = require_permission(Permission.VIEW_NETWORK_METADATA)


def _require_capture(request: Request, capture_id: str) -> None:
    with request.app.state.db.connect() as conn:
        if packets_store.get_capture(conn, capture_id) is None:
            raise HTTPException(status_code=404, detail="capture not found")


@router.get("/captures/{capture_id}/hosts")
def hosts_list(
    capture_id: str,
    request: Request,
    limit: int = Query(default=200, ge=1, le=1000),
    session: dict = Depends(_META),
) -> dict:
    _require_capture(request, capture_id)
    with request.app.state.db.connect() as conn:
        return {"hosts": analysis_store.list_hosts(conn, capture_id, limit=limit)}


@router.get("/captures/{capture_id}/hosts/{ip}")
def host_detail(
    capture_id: str,
    ip: str,
    request: Request,
    session: dict = Depends(_META),
) -> dict:
    _require_capture(request, capture_id)
    with request.app.state.db.connect() as conn:
        detail = analysis_store.get_host(conn, capture_id, ip)
    if detail is None:
        raise HTTPException(status_code=404, detail="host not found")
    return detail


@router.get("/captures/{capture_id}/dns")
def dns_list(
    capture_id: str,
    request: Request,
    qname: str | None = Query(default=None, min_length=1, max_length=255),
    rcode: str | None = Query(default=None, min_length=1, max_length=32),
    qtype: str | None = Query(default=None, min_length=1, max_length=32),
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    session: dict = Depends(_META),
) -> dict:
    _require_capture(request, capture_id)
    with request.app.state.db.connect() as conn:
        return analysis_store.list_dns(
            conn,
            capture_id,
            limit=limit,
            offset=offset,
            qname=qname,
            rcode=rcode,
            qtype=qtype,
        )


@router.get("/captures/{capture_id}/http")
def http_list(
    capture_id: str,
    request: Request,
    host: str | None = Query(default=None, min_length=1, max_length=255),
    method: str | None = Query(default=None, min_length=1, max_length=16),
    status: int | None = Query(default=None, ge=100, le=599),
    kind: str | None = Query(default=None, pattern="^(request|response)$"),
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    session: dict = Depends(_META),
) -> dict:
    _require_capture(request, capture_id)
    with request.app.state.db.connect() as conn:
        return analysis_store.list_http(
            conn,
            capture_id,
            limit=limit,
            offset=offset,
            host=host,
            method=method,
            status=status,
            kind=kind,
        )


@router.get("/captures/{capture_id}/tls")
def tls_list(
    capture_id: str,
    request: Request,
    sni: str | None = Query(default=None, min_length=1, max_length=255),
    version: str | None = Query(default=None, min_length=1, max_length=32),
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    session: dict = Depends(_META),
) -> dict:
    _require_capture(request, capture_id)
    with request.app.state.db.connect() as conn:
        return analysis_store.list_tls(
            conn,
            capture_id,
            limit=limit,
            offset=offset,
            sni=sni,
            version=version,
        )


@router.get("/captures/{capture_id}/stats")
def capture_stats(
    capture_id: str,
    request: Request,
    session: dict = Depends(_META),
) -> dict:
    _require_capture(request, capture_id)
    with request.app.state.db.connect() as conn:
        result = analysis_store.stats(conn, capture_id)
    if not has_permission(session["role"], Permission.VIEW_FINDINGS):
        result["findings"] = {
            "available": False,
            "note": "requires VIEW_FINDINGS permission",
        }
    if not has_permission(session["role"], Permission.VIEW_SENSITIVE_METADATA):
        result["sensitive_data"] = {
            "available": False,
            "note": "requires VIEW_SENSITIVE_METADATA permission",
        }
    return result


@router.get("/search")
def search(
    request: Request,
    capture_id: str = Query(min_length=1, max_length=64),
    q: str = Query(default="", max_length=512),
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    session: dict = Depends(_META),
) -> dict:
    _require_capture(request, capture_id)
    try:
        where_sql, params = compile_query(q)
    except QueryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    with request.app.state.db.connect() as conn:
        result = packets_store.search_packets(
            conn, capture_id, where_sql, params, limit=limit, offset=offset
        )
    return result


@router.get("/search/fields")
def search_fields(session: dict = Depends(_META)) -> dict:
    return {
        "fields": sorted(FIELDS.keys()),
        "operators": [
            "=",
            "==",
            "!=",
            ">",
            ">=",
            "<",
            "<=",
            "~",
            "contains",
            "startswith",
            "endswith",
        ],
        "deferred": {
            field: note for field, note in sorted(DEFERRED_FIELDS.items())
        },
    }
