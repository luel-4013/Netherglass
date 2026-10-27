"""M6 endpoints: flow-log and Kubernetes telemetry integrations, tunnels.

Permission model:
- Tunnel metadata and K8s correlation are network metadata
  (VIEW_NETWORK_METADATA).
- Imports mutate the dataset; CONTROL_CAPTURE is required (auditor cannot).
  Flow-log imports are refused while the emergency stop is active.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..ingest import flowlogs as flowlogs_mod
from ..ingest import k8s as k8s_mod
from ..security.rbac import Permission
from ..store import analysis as analysis_store
from ..store import packets as packets_store
from .deps import require_csrf, require_permission

router = APIRouter(prefix="/api", tags=["integrations"])

_META = require_permission(Permission.VIEW_NETWORK_METADATA)
_CONTROL = require_permission(Permission.CONTROL_CAPTURE)


class FlowlogImportRequest(BaseModel):
    path: str = Field(min_length=1, max_length=4096)
    format: str = Field(default="auto", max_length=32)
    label: str | None = Field(default=None, max_length=120)


class K8sImportRequest(BaseModel):
    inventory: dict | None = None
    path: str | None = Field(default=None, max_length=4096)
    label: str | None = Field(default=None, max_length=120)


def _require_capture(request: Request, capture_id: str) -> None:
    with request.app.state.db.connect() as conn:
        if packets_store.get_capture(conn, capture_id) is None:
            raise HTTPException(status_code=404, detail="capture not found")


@router.post("/integrations/flowlogs")
def flowlog_import(
    body: FlowlogImportRequest,
    request: Request,
    session: dict = Depends(_CONTROL),
    _csrf: dict = Depends(require_csrf),
) -> dict:
    if request.app.state.emergency.is_stopped():
        raise HTTPException(
            status_code=423,
            detail="flow-log import refused: emergency security stop is active",
        )
    try:
        return flowlogs_mod.import_flowlogs(
            request.app.state.db,
            Path(body.path),
            actor=session["username"],
            fmt=body.format,
            label=body.label,
        )
    except flowlogs_mod.FlowlogError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/integrations/k8s")
def k8s_import(
    body: K8sImportRequest,
    request: Request,
    session: dict = Depends(_CONTROL),
    _csrf: dict = Depends(require_csrf),
) -> dict:
    if request.app.state.emergency.is_stopped():
        raise HTTPException(
            status_code=423,
            detail="inventory import refused: emergency security stop is active",
        )
    inventory = body.inventory
    if inventory is None:
        if not body.path:
            raise HTTPException(
                status_code=400, detail="provide 'inventory' or 'path'"
            )
        path = Path(body.path).expanduser()
        if not path.is_file():
            raise HTTPException(status_code=404, detail=f"file not found: {path}")
        if path.stat().st_size > 64 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="inventory file too large")
        try:
            inventory = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=400, detail=f"invalid inventory JSON: {exc}"
            ) from exc
    try:
        return k8s_mod.import_inventory(
            request.app.state.db,
            inventory,
            actor=session["username"],
            label=body.label,
        )
    except k8s_mod.K8sError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/captures/{capture_id}/tunnels")
def capture_tunnels(
    capture_id: str,
    request: Request,
    session: dict = Depends(_META),
) -> dict:
    _require_capture(request, capture_id)
    with request.app.state.db.connect() as conn:
        tunnels = analysis_store.list_tunnels(conn, capture_id)
    return {"capture_id": capture_id, "tunnels": tunnels}


@router.get("/k8s/entities")
def k8s_entities(
    request: Request,
    kind: str | None = Query(default=None, max_length=32),
    namespace: str | None = Query(default=None, max_length=253),
    limit: int = Query(default=500, ge=1, le=2000),
    session: dict = Depends(_META),
) -> dict:
    if kind and kind not in ("node", "pod", "service", "namespace"):
        raise HTTPException(status_code=400, detail="invalid kind")
    with request.app.state.db.connect() as conn:
        entities = k8s_mod.list_entities(
            conn, kind=kind, namespace=namespace, limit=limit
        )
    return {"entities": entities}


@router.get("/captures/{capture_id}/k8s-correlation")
def k8s_correlation(
    capture_id: str,
    request: Request,
    limit: int = Query(default=200, ge=1, le=1000),
    session: dict = Depends(_META),
) -> dict:
    _require_capture(request, capture_id)
    with request.app.state.db.connect() as conn:
        return k8s_mod.correlate_capture(conn, capture_id, limit=limit)
