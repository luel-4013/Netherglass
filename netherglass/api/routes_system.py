"""System endpoints: health, interfaces, readiness, config, emergency controls."""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ..config import CAPTURE_PROFILES
from ..interfaces import capture_readiness, interfaces_as_dicts
from ..security.rbac import Permission, has_permission
from ..version import __version__
from .deps import require_csrf, require_permission

router = APIRouter(prefix="/api", tags=["system"])

CONFIRM_PHRASE = "EMERGENCY STOP"


class EmergencyStopRequest(BaseModel):
    confirm: str = ""
    reason: str | None = None


class EmergencyRecoverRequest(BaseModel):
    reason: str = ""


@router.get("/health")
def health(request: Request) -> dict:
    return {
        "status": "ok",
        "version": __version__,
        "emergency_stopped": request.app.state.emergency.is_stopped(),
    }


@router.get("/system/status")
def system_status(
    request: Request,
    session: dict = Depends(require_permission(Permission.VIEW_NETWORK_METADATA)),
) -> dict:
    config = request.app.state.config
    return {
        "emergency": request.app.state.emergency.status(),
        "profile": config.profile,
        "network_exposed": config.is_network_exposed,
    }


@router.get("/system/interfaces")
def interfaces(
    session: dict = Depends(require_permission(Permission.VIEW_NETWORK_METADATA)),
) -> dict:
    return {"interfaces": interfaces_as_dicts()}


@router.get("/system/readiness")
def readiness(
    session: dict = Depends(require_permission(Permission.VIEW_NETWORK_METADATA)),
) -> dict:
    return capture_readiness()


@router.get("/system/config")
def config_view(
    request: Request,
    session: dict = Depends(require_permission(Permission.VIEW_NETWORK_METADATA)),
) -> dict:
    config = request.app.state.config
    return {
        "profile": config.profile,
        "profiles": [asdict(profile) for profile in CAPTURE_PROFILES.values()],
        "scope": asdict(config.scope),
        "serve": {
            "host": config.serve.host,
            "port": config.serve.port,
            "behind_tls": config.serve.behind_tls,
        },
        "network_exposed": config.is_network_exposed,
        "warnings": config.warnings(),
    }


@router.post("/system/emergency-stop")
def emergency_stop(
    payload: EmergencyStopRequest,
    request: Request,
    session: dict = Depends(require_csrf),
) -> dict:
    if not has_permission(session["role"], Permission.TRIGGER_EMERGENCY_STOP):
        raise HTTPException(
            status_code=403, detail="missing permission: TRIGGER_EMERGENCY_STOP"
        )
    if payload.confirm.strip() != CONFIRM_PHRASE:
        raise HTTPException(
            status_code=400,
            detail=f"confirmation phrase mismatch; expected '{CONFIRM_PHRASE}'",
        )
    return request.app.state.emergency.trigger(
        actor=session["username"], reason=payload.reason
    )


@router.post("/system/emergency-recover")
def emergency_recover(
    payload: EmergencyRecoverRequest,
    request: Request,
    session: dict = Depends(require_csrf),
) -> dict:
    if not has_permission(session["role"], Permission.RECOVER_EMERGENCY_STOP):
        raise HTTPException(
            status_code=403, detail="missing permission: RECOVER_EMERGENCY_STOP"
        )
    if not payload.reason.strip():
        raise HTTPException(status_code=400, detail="recovery reason is required")
    if not request.app.state.emergency.is_stopped():
        raise HTTPException(
            status_code=400, detail="system is not in emergency stop state"
        )
    return request.app.state.emergency.recover(
        actor=session["username"], reason=payload.reason
    )
