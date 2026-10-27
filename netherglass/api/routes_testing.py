"""M7 endpoints: controlled testing (separate subsystem, spec sections 48-56).

Permission model:
- Viewing scope/tests: VIEW_FINDINGS (investigation data).
- Creating a test plan: CREATE_CONTROLLED_TEST (analyst+).
- Executing/aborting a test: EXECUTE_CONTROLLED_TEST (admin only) + CSRF +
  explicit confirmation phrase.
- Executions are refused during emergency stop and re-validated against the
  active testing scope at creation and execution time (fail closed).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..security.audit import append_event
from ..security.rbac import Permission
from ..testing_runner import CONFIRM_PHRASE, ControlledTestError
from ..testing_scope import ScopeError, ScopeViolation, scope_summary
from .deps import require_csrf, require_permission

router = APIRouter(prefix="/api", tags=["testing"])

_FINDINGS = require_permission(Permission.VIEW_FINDINGS)
_CREATE = require_permission(Permission.CREATE_CONTROLLED_TEST)
_EXECUTE = require_permission(Permission.EXECUTE_CONTROLLED_TEST)


class ControlledTestCreate(BaseModel):
    authorization_ref: str = Field(min_length=1, max_length=200)
    target: str = Field(min_length=1, max_length=253)
    test_type: str = Field(min_length=1, max_length=40)
    port: int | None = Field(default=None, ge=1, le=65535)
    artifact_id: str | None = Field(default=None, max_length=32)
    case_id: str | None = Field(default=None, max_length=32)
    dry_run: bool = True
    rate_limit_ms: int = Field(default=1000, ge=100, le=60000)
    max_requests: int = Field(default=5, ge=1, le=50)
    timeout_ms: int = Field(default=5000, ge=200, le=30000)
    window_start: str | None = Field(default=None, max_length=40)
    window_end: str | None = Field(default=None, max_length=40)


class ExecuteRequest(BaseModel):
    confirm: str = Field(min_length=1, max_length=64)


@router.get("/testing/scope")
def testing_scope(
    request: Request, session: dict = Depends(_FINDINGS)
) -> dict:
    return scope_summary(request.app.state.config.data_dir)


@router.get("/testing/tests")
def list_tests(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    session: dict = Depends(_FINDINGS),
) -> dict:
    return {"tests": request.app.state.testing.list_tests(limit=limit)}


@router.post("/testing/tests")
def create_test(
    body: ControlledTestCreate,
    request: Request,
    session: dict = Depends(_CREATE),
    _csrf: dict = Depends(require_csrf),
) -> dict:
    try:
        test = request.app.state.testing.create_plan(
            actor=session["username"],
            authorization_ref=body.authorization_ref,
            target=body.target,
            test_type=body.test_type,
            port=body.port,
            artifact_id=body.artifact_id,
            case_id=body.case_id,
            dry_run=body.dry_run,
            rate_limit_ms=body.rate_limit_ms,
            max_requests=body.max_requests,
            timeout_ms=body.timeout_ms,
            window_start=body.window_start,
            window_end=body.window_end,
        )
    except (ControlledTestError, ScopeViolation) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ScopeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    with request.app.state.db.connect() as conn:
        append_event(
            conn,
            actor=session["username"],
            action="CONTROLLED_TEST_CREATED",
            target=test["id"],
            details={
                "authorization_ref": test["authorization_ref"],
                "target": test["target"],
                "port": test["port"],
                "test_type": test["test_type"],
                "artifact_id": test["artifact_id"],
                "dry_run": bool(test["dry_run"]),
            },
        )
    return test


@router.get("/testing/tests/{test_id}")
def test_detail(
    test_id: str,
    request: Request,
    session: dict = Depends(_FINDINGS),
) -> dict:
    try:
        return request.app.state.testing.get(test_id)
    except ControlledTestError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/testing/tests/{test_id}/execute")
def execute_test(
    test_id: str,
    body: ExecuteRequest,
    request: Request,
    session: dict = Depends(_EXECUTE),
    _csrf: dict = Depends(require_csrf),
) -> dict:
    if body.confirm.strip() != CONFIRM_PHRASE:
        raise HTTPException(
            status_code=400,
            detail=f"confirmation phrase must be exactly {CONFIRM_PHRASE!r}",
        )
    if request.app.state.emergency.is_stopped():
        raise HTTPException(
            status_code=423,
            detail="controlled tests are disabled during emergency stop",
        )
    try:
        test = request.app.state.testing.execute(test_id, actor=session["username"])
    except ControlledTestError as exc:
        message = str(exc)
        code = 404 if "not found" in message else 409
        raise HTTPException(status_code=code, detail=message) from exc
    with request.app.state.db.connect() as conn:
        append_event(
            conn,
            actor=session["username"],
            action="CONTROLLED_TEST_EXECUTED",
            target=test_id,
            details={
                "authorization_ref": test["authorization_ref"],
                "target": test["target"],
                "test_type": test["test_type"],
                "dry_run": bool(test["dry_run"]),
                "artifact_id": test["artifact_id"],
            },
        )
    return test


@router.post("/testing/tests/{test_id}/abort")
def abort_test(
    test_id: str,
    request: Request,
    session: dict = Depends(_EXECUTE),
    _csrf: dict = Depends(require_csrf),
) -> dict:
    try:
        test = request.app.state.testing.abort(test_id, actor=session["username"])
    except ControlledTestError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    with request.app.state.db.connect() as conn:
        append_event(
            conn,
            actor=session["username"],
            action="CONTROLLED_TEST_ABORT_REQUESTED",
            target=test_id,
            details={"status": test["status"]},
        )
    return test
