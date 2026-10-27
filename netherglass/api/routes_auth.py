"""Authentication endpoints: session info, login, logout."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from ..security.audit import append_event
from ..security.auth import (
    SESSION_COOKIE,
    authenticate,
    create_session,
    revoke_session,
)
from ..security.rbac import permissions_for
from .deps import current_session, require_csrf

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


@router.get("/session")
def session_info(session: dict | None = Depends(current_session)) -> dict:
    if session is None:
        return {"authenticated": False, "permissions": []}
    return {
        "authenticated": True,
        "user": {"username": session["username"], "role": session["role"]},
        "csrf_token": session["csrf_token"],
        "permissions": permissions_for(session["role"]),
    }


@router.post("/login")
def login(payload: LoginRequest, request: Request, response: Response) -> dict:
    config = request.app.state.config
    db = request.app.state.db
    limiter = request.app.state.limiter
    ip = request.client.host if request.client else "unknown"
    key = f"{ip}|{payload.username.lower()}"

    if limiter.is_locked(key):
        raise HTTPException(
            status_code=429, detail="too many failed attempts; try again later"
        )

    with db.connect() as conn:
        user = authenticate(conn, payload.username, payload.password)
        session_id = csrf_token = None
        if user is None:
            append_event(
                conn,
                actor=payload.username[:64],
                action="LOGIN_FAILURE",
                target=ip,
                details={},
            )
        else:
            limiter.reset(key)
            session_id, csrf_token = create_session(
                conn,
                user["id"],
                config.serve.session_hours,
                ip,
                request.headers.get("user-agent"),
            )
            append_event(
                conn,
                actor=user["username"],
                action="LOGIN_SUCCESS",
                target=ip,
                details={},
            )

    if user is None or session_id is None or csrf_token is None:
        limiter.record_failure(key)
        raise HTTPException(status_code=401, detail="invalid credentials")

    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        httponly=True,
        samesite="strict",
        secure=config.serve.behind_tls,
        max_age=config.serve.session_hours * 3600,
        path="/",
    )
    return {
        "authenticated": True,
        "user": {"username": user["username"], "role": user["role"]},
        "csrf_token": csrf_token,
        "permissions": permissions_for(user["role"]),
    }


@router.post("/logout")
def logout(
    request: Request, response: Response, session: dict = Depends(require_csrf)
) -> dict:
    session_id = request.cookies.get(SESSION_COOKIE)
    with request.app.state.db.connect() as conn:
        if session_id:
            revoke_session(conn, session_id)
        append_event(
            conn, actor=session["username"], action="LOGOUT", target=None, details={}
        )
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}
