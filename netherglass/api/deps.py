"""FastAPI dependencies: session resolution, permission and CSRF enforcement."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request

from ..security.auth import SESSION_COOKIE, get_session
from ..security.rbac import Permission, has_permission


def current_session(request: Request) -> dict | None:
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        return None
    db = request.app.state.db
    with db.connect() as conn:
        return get_session(conn, session_id)


def require_user(session: dict | None = Depends(current_session)) -> dict:
    if session is None:
        raise HTTPException(status_code=401, detail="authentication required")
    return session


def require_permission(permission: Permission):
    def dependency(session: dict = Depends(require_user)) -> dict:
        if not has_permission(session["role"], permission):
            raise HTTPException(
                status_code=403, detail=f"missing permission: {permission.value}"
            )
        return session

    return dependency


def require_csrf(request: Request, session: dict = Depends(require_user)) -> dict:
    token = request.headers.get("X-CSRF-Token")
    if not token or token != session["csrf_token"]:
        raise HTTPException(status_code=403, detail="invalid or missing CSRF token")
    return session
