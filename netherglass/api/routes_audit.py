"""Audit log endpoints: hash-chained event listing with chain verification."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from ..security.audit import list_events, verify_chain
from ..security.rbac import Permission
from .deps import require_permission

router = APIRouter(prefix="/api", tags=["audit"])


@router.get("/audit")
def audit_log(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    session: dict = Depends(require_permission(Permission.VIEW_AUDIT_LOG)),
) -> dict:
    with request.app.state.db.connect() as conn:
        events = list_events(conn, limit)
        chain_valid, chain_length = verify_chain(conn)
    return {"events": events, "chain_valid": chain_valid, "chain_length": chain_length}
