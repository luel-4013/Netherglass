"""FastAPI application factory.

Security posture:
- Authentication is enforced for every data endpoint; the only public
  endpoints are /api/health and /api/auth/session.
- Security headers on all responses; no API docs endpoints are exposed.
- Origin checks reject cross-origin state-changing requests.
- First run bootstraps a single admin account and writes its credentials to a
  0600 file in the data directory; the operator changes the password after
  first login (M2 adds the change-password flow).
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from ..config import AppConfig, ensure_layout
from ..emergency import EmergencyStop
from ..security.audit import append_event
from ..security.auth import LoginLimiter, create_user
from ..store.db import Database
from ..version import __version__
from ..capture.engine import CaptureEngine
from ..testing_runner import ControlledTestRunner
from . import (
    routes_analysis,
    routes_audit,
    routes_auth,
    routes_capture,
    routes_evidence,
    routes_integrations,
    routes_system,
    routes_testing,
    routes_websec,
)


def bootstrap_admin(config: AppConfig, db: Database) -> None:
    with db.connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
        if row["n"]:
            return
        password = secrets.token_urlsafe(12)
        create_user(conn, "admin", password, "admin")
        creds_path = config.data_dir / "BOOTSTRAP_CREDENTIALS.txt"
        creds_path.write_text(
            "Netherglass bootstrap credentials\n"
            "username: admin\n"
            f"password: {password}\n\n"
            "Change this password after first login and delete this file.\n"
        )
        os.chmod(creds_path, 0o600)
        append_event(
            conn,
            actor="system",
            action="USER_BOOTSTRAP",
            target="admin",
            details={
                "note": "bootstrap admin created; credentials file written; "
                "change password after first login"
            },
        )


def create_app(config: AppConfig) -> FastAPI:
    config.validate()
    ensure_layout(config.data_dir)
    db = Database(config.db_path())
    db.migrate()
    bootstrap_admin(config, db)

    app = FastAPI(
        title="Netherglass",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.config = config
    app.state.db = db
    app.state.emergency = EmergencyStop(db)
    app.state.limiter = LoginLimiter()
    app.state.capture = CaptureEngine(config, db, app.state.emergency)
    app.state.testing = ControlledTestRunner(config, db, app.state.emergency)

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin:
                origin_host = urlparse(origin).netloc
                if origin_host and origin_host != request.headers.get("host"):
                    return JSONResponse(
                        {"detail": "cross-origin request rejected"}, status_code=403
                    )
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store"
        return response

    app.include_router(routes_auth.router)
    app.include_router(routes_system.router)
    app.include_router(routes_audit.router)
    app.include_router(routes_capture.router)
    app.include_router(routes_analysis.router)
    app.include_router(routes_evidence.router)
    app.include_router(routes_websec.router)
    app.include_router(routes_integrations.router)
    app.include_router(routes_testing.router)
    _mount_web(app)
    return app


def _mount_web(app: FastAPI) -> None:
    dist = Path(
        os.environ.get(
            "NETHERGLASS_WEB_DIST",
            Path(__file__).resolve().parents[2] / "web" / "dist",
        )
    )
    if not (dist / "index.html").exists():
        return
    assets = dist / "assets"
    if assets.exists():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        if full_path.startswith("api"):
            raise HTTPException(status_code=404)
        candidate = dist / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(dist / "index.html")
