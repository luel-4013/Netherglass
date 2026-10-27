"""M5 endpoints: web security analysis, investigation, timeline, graph, reports.

Permission model:
- Web/application inventory, cookies, headers, timeline and graph are network
  metadata (VIEW_NETWORK_METADATA). Findings/evidence timeline entries are only
  included for roles that may see them.
- Token fingerprints and data-flow maps are sensitive metadata.
- Cases require VIEW_FINDINGS to read; only admin/analyst may mutate.
- Reports: standard export requires EXPORT_EVIDENCE, restricted export requires
  EXPORT_SENSITIVE_EVIDENCE and is always audited. Sensitive values are only
  decrypted in the restricted path and never cached.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from ..analysis import report as report_mod
from ..security.audit import append_event
from ..security.rbac import Permission, has_permission
from ..store import cases as cases_store
from ..store import graph as graph_store
from ..store import packets as packets_store
from ..store import timeline as timeline_store
from ..store import websec as websec_store
from .deps import require_csrf, require_permission

router = APIRouter(prefix="/api", tags=["websec"])

_META = require_permission(Permission.VIEW_NETWORK_METADATA)
_SENSITIVE = require_permission(Permission.VIEW_SENSITIVE_METADATA)
_FINDINGS = require_permission(Permission.VIEW_FINDINGS)
_EXPORT = require_permission(Permission.EXPORT_EVIDENCE)
_EXPORT_SENSITIVE = require_permission(Permission.EXPORT_SENSITIVE_EVIDENCE)


def _require_capture(request: Request, capture_id: str) -> None:
    with request.app.state.db.connect() as conn:
        if packets_store.get_capture(conn, capture_id) is None:
            raise HTTPException(status_code=404, detail="capture not found")


@router.get("/captures/{capture_id}/web/apps")
def web_apps(
    capture_id: str,
    request: Request,
    session: dict = Depends(_META),
) -> dict:
    _require_capture(request, capture_id)
    with request.app.state.db.connect() as conn:
        return websec_store.app_inventory(conn, capture_id)


@router.get("/captures/{capture_id}/web/cookies")
def web_cookies(
    capture_id: str,
    request: Request,
    session: dict = Depends(_META),
) -> dict:
    _require_capture(request, capture_id)
    with request.app.state.db.connect() as conn:
        return websec_store.list_cookies(conn, capture_id)


@router.get("/captures/{capture_id}/web/headers")
def web_headers(
    capture_id: str,
    request: Request,
    session: dict = Depends(_META),
) -> dict:
    _require_capture(request, capture_id)
    with request.app.state.db.connect() as conn:
        return websec_store.list_headers(conn, capture_id)


@router.get("/captures/{capture_id}/web/tokens")
def web_tokens(
    capture_id: str,
    request: Request,
    session: dict = Depends(_SENSITIVE),
) -> dict:
    _require_capture(request, capture_id)
    with request.app.state.db.connect() as conn:
        return websec_store.list_tokens(conn, capture_id)


@router.get("/captures/{capture_id}/web/flows")
def web_flows(
    capture_id: str,
    request: Request,
    session: dict = Depends(_SENSITIVE),
) -> dict:
    _require_capture(request, capture_id)
    with request.app.state.db.connect() as conn:
        return websec_store.data_flows(conn, capture_id)


@router.get("/captures/{capture_id}/timeline")
def timeline(
    capture_id: str,
    request: Request,
    kind: str | None = Query(default=None, max_length=32),
    severity: str | None = Query(default=None, max_length=16),
    host: str | None = Query(default=None, max_length=255),
    domain: str | None = Query(default=None, max_length=255),
    start: float | None = Query(default=None),
    end: float | None = Query(default=None),
    limit: int = Query(default=300, ge=1, le=1000),
    session: dict = Depends(_META),
) -> dict:
    _require_capture(request, capture_id)
    kinds = {item.strip().lower() for item in kind.split(",")} if kind else None
    if kinds and not has_permission(session["role"], Permission.VIEW_FINDINGS):
        kinds.discard("finding")
    if kinds and not has_permission(
        session["role"], Permission.VIEW_SENSITIVE_METADATA
    ):
        kinds.discard("evidence")
    if not has_permission(session["role"], Permission.VIEW_FINDINGS) and not kinds:
        kinds = {"dns", "tls", "http", "audit"}
    with request.app.state.db.connect() as conn:
        return timeline_store.build_timeline(
            conn,
            capture_id,
            limit=limit,
            kinds=kinds,
            severity=severity,
            host=host,
            domain=domain,
            start=start,
            end=end,
        )


@router.get("/captures/{capture_id}/graph")
def graph(
    capture_id: str,
    request: Request,
    mode: str = Query(default="network", pattern="^(network|connection)$"),
    session: dict = Depends(_META),
) -> dict:
    _require_capture(request, capture_id)
    with request.app.state.db.connect() as conn:
        if mode == "connection":
            return graph_store.connection_graph(conn, capture_id)
        return graph_store.network_graph(conn, capture_id)


# ------------------------------------------------------------------- cases


class CaseCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    summary: str = Field(default="", max_length=4000)


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    summary: str | None = Field(default=None, max_length=4000)
    status: str | None = Field(default=None, pattern="^(OPEN|CLOSED)$")


class CaseItemCreate(BaseModel):
    item_type: str = Field(pattern="^(finding|evidence|host|domain|note|capture)$")
    item_id: str = Field(min_length=1, max_length=128)
    capture_id: str | None = Field(default=None, max_length=64)
    note: str | None = Field(default=None, max_length=2000)


def _require_case_editor(session: dict = Depends(_FINDINGS)) -> dict:
    if session["role"] not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="auditors have read-only case access")
    return session


@router.get("/cases")
def case_list(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    session: dict = Depends(_FINDINGS),
) -> dict:
    with request.app.state.db.connect() as conn:
        return {"cases": cases_store.list_cases(conn, limit=limit)}


@router.post("/cases")
def case_create(
    body: CaseCreate,
    request: Request,
    session: dict = Depends(_require_case_editor),
    _csrf: dict = Depends(require_csrf),
) -> dict:
    with request.app.state.db.connect() as conn:
        try:
            case = cases_store.create_case(
                conn,
                title=body.title,
                summary=body.summary,
                created_by=session["username"],
            )
        except cases_store.CaseError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        append_event(
            conn,
            actor=session["username"],
            action="CASE_CREATED",
            target=case["id"],
            details={"title": case["title"]},
        )
    return case


@router.get("/cases/{case_id}")
def case_detail(
    case_id: str,
    request: Request,
    session: dict = Depends(_FINDINGS),
) -> dict:
    with request.app.state.db.connect() as conn:
        case = cases_store.get_case(conn, case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="case not found")
        case["timeline"] = cases_store.case_timeline(conn, case_id)
    return case


@router.patch("/cases/{case_id}")
def case_update(
    case_id: str,
    body: CaseUpdate,
    request: Request,
    session: dict = Depends(_require_case_editor),
    _csrf: dict = Depends(require_csrf),
) -> dict:
    with request.app.state.db.connect() as conn:
        try:
            case = cases_store.update_case(
                conn,
                case_id,
                title=body.title,
                summary=body.summary,
                status=body.status,
            )
        except cases_store.CaseError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        append_event(
            conn,
            actor=session["username"],
            action="CASE_UPDATED",
            target=case_id,
            details={
                "status": case["status"],
                "title": case["title"],
            },
        )
    return case


@router.post("/cases/{case_id}/items")
def case_add_item(
    case_id: str,
    body: CaseItemCreate,
    request: Request,
    session: dict = Depends(_require_case_editor),
    _csrf: dict = Depends(require_csrf),
) -> dict:
    with request.app.state.db.connect() as conn:
        try:
            case = cases_store.add_item(
                conn,
                case_id,
                item_type=body.item_type,
                item_id=body.item_id,
                capture_id=body.capture_id,
                note=body.note,
                added_by=session["username"],
            )
        except cases_store.CaseError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        append_event(
            conn,
            actor=session["username"],
            action="CASE_ITEM_ADDED",
            target=case_id,
            details={"item_type": body.item_type, "item_id": body.item_id},
        )
    return case


@router.delete("/cases/{case_id}/items/{item_id}")
def case_remove_item(
    case_id: str,
    item_id: int,
    request: Request,
    session: dict = Depends(_require_case_editor),
    _csrf: dict = Depends(require_csrf),
) -> dict:
    with request.app.state.db.connect() as conn:
        if cases_store.get_case(conn, case_id) is None:
            raise HTTPException(status_code=404, detail="case not found")
        case = cases_store.remove_item(conn, case_id, item_id)
        append_event(
            conn,
            actor=session["username"],
            action="CASE_ITEM_REMOVED",
            target=case_id,
            details={"item_id": item_id},
        )
    return case


# ----------------------------------------------------------------- reports


@router.get("/captures/{capture_id}/report")
def capture_report(
    capture_id: str,
    request: Request,
    format: str = Query(default="html", pattern="^(html|json)$"),
    restricted: bool = Query(default=False),
    session: dict = Depends(_EXPORT),
) -> Response:
    _require_capture(request, capture_id)
    if restricted and not has_permission(
        session["role"], Permission.EXPORT_SENSITIVE_EVIDENCE
    ):
        raise HTTPException(
            status_code=403,
            detail="missing permission: EXPORT_SENSITIVE_EVIDENCE",
        )
    if request.app.state.emergency.is_stopped():
        raise HTTPException(
            status_code=423,
            detail="emergency security stop is active; exports are disabled",
        )
    try:
        with request.app.state.db.connect() as conn:
            report = report_mod.build_report(
                conn,
                capture_id,
                data_dir=request.app.state.config.data_dir,
                restricted=restricted,
                generated_by=session["username"],
            )
            append_event(
                conn,
                actor=session["username"],
                action="REPORT_EXPORTED",
                target=capture_id,
                details={
                    "format": format,
                    "restricted": restricted,
                    "findings": len(report["report"]["findings"]),
                    "evidence": len(report["report"]["evidence"]),
                },
            )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    filename = f"netherglass-{capture_id}-{'restricted' if restricted else 'standard'}.{format}"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    if format == "json":
        return JSONResponse(report, headers=headers)
    return HTMLResponse(report_mod.render_html(report), headers=headers)
