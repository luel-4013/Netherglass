"""M4 endpoints: findings, sealed evidence metadata, and audited reveal.

Contract (spec sections 19-24, 34-36):
- Listing evidence exposes metadata only; the sealed value is never returned.
- Reveal is a separate, CSRF-protected, permission-gated action that requires a
  stated reason and writes an audit event before returning the value.
- Values are returned with a short client-side auto-hide hint; the API keeps no
  cache (global middleware sets Cache-Control: no-store).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..analysis import rules as rules_mod
from ..security.audit import append_event
from ..security.rbac import Permission
from ..store import evidence as evidence_store
from ..store import findings as findings_store
from ..store import packets as packets_store
from .deps import require_csrf, require_permission

router = APIRouter(prefix="/api", tags=["evidence"])

REVEAL_AUTO_HIDE_SECONDS = 30

_META = require_permission(Permission.VIEW_SENSITIVE_METADATA)
_REVEAL = require_permission(Permission.VIEW_SENSITIVE_VALUES)
_FINDINGS = require_permission(Permission.VIEW_FINDINGS)
_DELETE = require_permission(Permission.DELETE_EVIDENCE)


def _require_capture(request: Request, capture_id: str) -> None:
    with request.app.state.db.connect() as conn:
        if packets_store.get_capture(conn, capture_id) is None:
            raise HTTPException(status_code=404, detail="capture not found")


def _get_evidence_or_404(request: Request, evidence_id: str) -> dict:
    with request.app.state.db.connect() as conn:
        row = evidence_store.get_evidence(conn, evidence_id)
    if row is None:
        raise HTTPException(status_code=404, detail="evidence not found")
    return row


class RevealBody(BaseModel):
    reason: str = Field(min_length=4, max_length=400)


class DeleteBody(BaseModel):
    reason: str = Field(min_length=4, max_length=400)


@router.get("/captures/{capture_id}/evidence")
def evidence_list(
    capture_id: str,
    request: Request,
    artifact_type: str | None = Query(default=None, min_length=2, max_length=64),
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    session: dict = Depends(_META),
) -> dict:
    _require_capture(request, capture_id)
    with request.app.state.db.connect() as conn:
        result = evidence_store.list_evidence(
            conn,
            capture_id,
            artifact_type=artifact_type,
            limit=limit,
            offset=offset,
        )
        result["summary"] = evidence_store.summary(conn, capture_id)
    return result


@router.get("/evidence/{evidence_id}")
def evidence_detail(
    evidence_id: str,
    request: Request,
    session: dict = Depends(_META),
) -> dict:
    return _get_evidence_or_404(request, evidence_id)


@router.delete("/evidence/{evidence_id}")
def evidence_delete(
    evidence_id: str,
    body: DeleteBody,
    request: Request,
    session: dict = Depends(_DELETE),
    _csrf: dict = Depends(require_csrf),
) -> dict:
    """Best-effort secure deletion: blob overwritten with zeros, fsynced, then
    unlinked; the row remains as a DELETED tombstone so the audit trail and
    chain of custody stay intact. Not a forensic guarantee on all filesystems
    (documented limitation)."""
    row = _get_evidence_or_404(request, evidence_id)
    if request.app.state.emergency.is_stopped():
        raise HTTPException(
            status_code=423,
            detail="emergency security stop is active; deletion is disabled",
        )
    with request.app.state.db.connect() as conn:
        try:
            updated = evidence_store.delete_evidence(
                request.app.state.config.data_dir,
                conn,
                evidence_id,
                reason=body.reason,
            )
        except evidence_store.EvidenceError as exc:
            raise HTTPException(status_code=exc.code, detail=str(exc)) from exc
        append_event(
            conn,
            actor=session["username"],
            action="EVIDENCE_DELETED",
            target=evidence_id,
            details={
                "capture_id": row["capture_id"],
                "artifact_type": row["artifact_type"],
                "reason": body.reason,
                "secure_delete": "zero-overwrite+fsync+unlink",
            },
        )
    return updated


@router.post("/evidence/{evidence_id}/reveal")
def evidence_reveal(
    evidence_id: str,
    body: RevealBody,
    request: Request,
    session: dict = Depends(_REVEAL),
    _csrf: dict = Depends(require_csrf),
) -> dict:
    row = _get_evidence_or_404(request, evidence_id)
    if request.app.state.emergency.is_stopped():
        raise HTTPException(
            status_code=423,
            detail="emergency security stop is active; reveal is disabled",
        )
    try:
        payload = evidence_store.reveal_value(
            request.app.state.config.data_dir, row
        )
    except evidence_store.EvidenceError as exc:
        raise HTTPException(status_code=exc.code, detail=str(exc)) from exc
    with request.app.state.db.connect() as conn:
        append_event(
            conn,
            actor=session["username"],
            action="REVEAL_SENSITIVE_VALUE",
            target=evidence_id,
            details={
                "capture_id": row["capture_id"],
                "artifact_type": row["artifact_type"],
                "field": row.get("field"),
                "reason": body.reason,
            },
        )
    return {
        **payload,
        "evidence_id": evidence_id,
        "auto_hide_seconds": REVEAL_AUTO_HIDE_SECONDS,
    }


@router.get("/captures/{capture_id}/findings")
def findings_list(
    capture_id: str,
    request: Request,
    severity: str | None = Query(default=None, min_length=4, max_length=16),
    confidence: str | None = Query(default=None, min_length=4, max_length=16),
    status: str | None = Query(default=None, min_length=4, max_length=16),
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    session: dict = Depends(_FINDINGS),
) -> dict:
    _require_capture(request, capture_id)
    with request.app.state.db.connect() as conn:
        result = findings_store.list_findings(
            conn,
            capture_id,
            severity=severity,
            confidence=confidence,
            status=status,
            limit=limit,
            offset=offset,
        )
        result["summary"] = findings_store.summary(conn, capture_id)
    return result


@router.get("/findings/{finding_id}")
def finding_detail(
    finding_id: str,
    request: Request,
    session: dict = Depends(_FINDINGS),
) -> dict:
    with request.app.state.db.connect() as conn:
        finding = findings_store.get_finding(conn, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return finding


@router.post("/captures/{capture_id}/analyze")
def analyze_capture(
    capture_id: str,
    request: Request,
    session: dict = Depends(_FINDINGS),
    _csrf: dict = Depends(require_csrf),
) -> dict:
    _require_capture(request, capture_id)
    try:
        with request.app.state.db.connect() as conn:
            count = rules_mod.run_and_store(
                conn, capture_id, data_dir=request.app.state.config.data_dir
            )
            append_event(
                conn,
                actor=session["username"],
                action="ANALYSIS_COMPLETED",
                target=capture_id,
                details={"findings": count, "trigger": "manual"},
            )
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"analysis failed: {exc}"
        ) from exc
    return {"capture_id": capture_id, "findings": count}
