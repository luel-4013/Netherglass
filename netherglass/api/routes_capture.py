"""Capture endpoints: live start/stop, offline import, packets and flows."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask

from ..config import AppConfig
from ..security.audit import append_event
from ..security.rbac import Permission, has_permission
from ..store import packets as packets_store
from .deps import require_csrf, require_permission

router = APIRouter(prefix="/api", tags=["capture"])

_META = require_permission(Permission.VIEW_NETWORK_METADATA)
_EXPORT = require_permission(Permission.EXPORT_EVIDENCE)


class CaptureStartRequest(BaseModel):
    interface: str = Field(min_length=1, max_length=64)
    bpf: str | None = Field(default=None, max_length=512)
    chunk_seconds: int = Field(default=5, ge=1, le=120)


class CaptureStopRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=256)


class ImportRequest(BaseModel):
    path: str = Field(min_length=1, max_length=4096)


@router.get("/capture/status")
def capture_status(request: Request, session: dict = Depends(_META)) -> dict:
    return request.app.state.capture.status()


def _require_capture_control(session: dict) -> None:
    if not has_permission(session["role"], Permission.CONTROL_CAPTURE):
        raise HTTPException(status_code=403, detail="missing permission: CONTROL_CAPTURE")


@router.post("/capture/start")
def capture_start(
    payload: CaptureStartRequest,
    request: Request,
    session: dict = Depends(require_csrf),
) -> dict:
    _require_capture_control(session)
    config = request.app.state.config
    if config.profile == "C" and not has_permission(
        session["role"], Permission.ENABLE_FULL_CAPTURE
    ):
        raise HTTPException(
            status_code=403,
            detail="profile C requires permission: ENABLE_FULL_CAPTURE",
        )
    from ..capture.engine import CaptureError

    try:
        return request.app.state.capture.start_live(
            payload.interface,
            actor=session["username"],
            bpf=payload.bpf,
            chunk_seconds=payload.chunk_seconds,
        )
    except CaptureError as exc:
        raise HTTPException(status_code=exc.code, detail=str(exc)) from exc


@router.post("/capture/stop")
def capture_stop(
    payload: CaptureStopRequest,
    request: Request,
    session: dict = Depends(require_csrf),
) -> dict:
    _require_capture_control(session)
    from ..capture.engine import CaptureError

    try:
        return request.app.state.capture.stop(
            actor=session["username"], reason=payload.reason
        )
    except CaptureError as exc:
        raise HTTPException(status_code=exc.code, detail=str(exc)) from exc


@router.post("/capture/import")
def capture_import(
    payload: ImportRequest,
    request: Request,
    session: dict = Depends(require_csrf),
) -> dict:
    _require_capture_control(session)
    from ..capture.engine import CaptureError

    try:
        return request.app.state.capture.import_file(
            Path(payload.path), actor=session["username"]
        )
    except CaptureError as exc:
        raise HTTPException(status_code=exc.code, detail=str(exc)) from exc


@router.get("/captures")
def captures_list(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    session: dict = Depends(_META),
) -> dict:
    with request.app.state.db.connect() as conn:
        return {"captures": packets_store.list_captures(conn, limit=limit)}


@router.get("/captures/{capture_id}")
def capture_detail(
    capture_id: str, request: Request, session: dict = Depends(_META)
) -> dict:
    with request.app.state.db.connect() as conn:
        row = packets_store.get_capture(conn, capture_id)
        if row is None:
            raise HTTPException(status_code=404, detail="capture not found")
        totals = packets_store.capture_totals(conn, capture_id)
    return {**row, **totals}


def _detect_pcap_format(path: Path) -> str | None:
    try:
        with path.open("rb") as handle:
            magic = handle.read(4)
    except OSError:
        return None
    if magic == b"\x0a\x0d\x0d\x0a":
        return "pcapng"
    if magic in (
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
    ):
        return "pcap"
    return None


def _raw_files(row: dict, config: AppConfig) -> list[Path]:
    directory = (
        Path(row["pcap_path"])
        if row.get("pcap_path")
        else config.data_dir / "captures" / row["id"]
    )
    if not directory.is_dir():
        return []
    manifest_path = directory / "manifest.json"
    names: list[str] = []
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text())
        except (OSError, json.JSONDecodeError):
            manifest = {}
        if manifest.get("source") == "import":
            source_dir = directory / "source"
            if source_dir.is_dir():
                return sorted(p for p in source_dir.iterdir() if p.is_file())
            return []
        names = [str(f.get("name") or "") for f in manifest.get("files") or []]
    files: list[Path] = []
    base = directory.resolve()
    for name in names:
        candidate = (directory / Path(name).name).resolve()
        if candidate.parent == base and candidate.is_file():
            files.append(candidate)
    if files:
        return files
    source_dir = directory / "source"
    if source_dir.is_dir():
        return sorted(p for p in source_dir.iterdir() if p.is_file())
    return sorted(directory.glob("*.pcapng")) + sorted(directory.glob("*.pcap"))


def _merge_files(files: list[Path], fmt: str, *, directory: Path) -> Path:
    mergecap = shutil.which("mergecap")
    if mergecap is None:
        raise HTTPException(
            status_code=500,
            detail="mergecap (wireshark-cli) is required to convert or merge raw files",
        )
    handle, temp_name = tempfile.mkstemp(
        prefix="export-", suffix=f".{fmt}", dir=str(directory)
    )
    os.close(handle)
    target = Path(temp_name)
    command = [
        mergecap,
        "-a",
        "-w",
        str(target),
        "-F",
        fmt,
        *(str(f) for f in files),
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=600, check=False
        )
    except subprocess.TimeoutExpired as exc:
        target.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail="export merge timed out") from exc
    if result.returncode != 0:
        target.unlink(missing_ok=True)
        detail = (result.stderr or result.stdout or "unknown error").strip()[:300]
        raise HTTPException(status_code=500, detail=f"mergecap failed: {detail}")
    return target


@router.get("/captures/{capture_id}/export")
def capture_export(
    capture_id: str,
    request: Request,
    fmt: str = Query(default="pcapng", alias="format", pattern="^(pcapng|pcap)$"),
    session: dict = Depends(_EXPORT),
) -> FileResponse:
    if request.app.state.emergency.is_stopped():
        raise HTTPException(
            status_code=423,
            detail="exports stopped: emergency security stop is active",
        )
    config = request.app.state.config
    with request.app.state.db.connect() as conn:
        row = packets_store.get_capture(conn, capture_id)
        if row is None:
            raise HTTPException(status_code=404, detail="capture not found")
        if row["status"] == "running":
            raise HTTPException(
                status_code=409,
                detail="capture is still running; stop it before exporting",
            )
        files = _raw_files(row, config)
        if not files:
            raise HTTPException(
                status_code=410,
                detail=(
                    "raw capture files are not retained for this capture "
                    "(metadata-only profile or files removed)"
                ),
            )
        converted = len(files) > 1 or _detect_pcap_format(files[0]) != fmt
        merged: Path | None = None
        if converted:
            merged = _merge_files(files, fmt, directory=files[0].parent)
            source = merged
        else:
            source = files[0]
        append_event(
            conn,
            actor=session["username"],
            action="EVIDENCE_EXPORTED",
            target=capture_id,
            details={
                "format": fmt,
                "files": len(files),
                "bytes": sum(f.stat().st_size for f in files),
                "converted": converted,
            },
        )
    background = (
        BackgroundTask(merged.unlink, missing_ok=True) if merged is not None else None
    )
    return FileResponse(
        source,
        media_type="application/vnd.tcpdump.pcap",
        filename=f"netherglass-{capture_id}.{fmt}",
        background=background,
    )


@router.get("/packets")
def packets_list(
    request: Request,
    capture_id: str = Query(min_length=1, max_length=64),
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    proto: str | None = Query(default=None, min_length=1, max_length=32),
    addr: str | None = Query(default=None, min_length=1, max_length=64),
    port: int | None = Query(default=None, ge=1, le=65535),
    session: dict = Depends(_META),
) -> dict:
    proto_clean = proto.lower().strip() if proto else None
    if proto_clean and not proto_clean.replace("-", "").isalnum():
        raise HTTPException(status_code=400, detail="invalid proto filter")
    with request.app.state.db.connect() as conn:
        return packets_store.list_packets(
            conn,
            capture_id,
            limit=limit,
            offset=offset,
            proto=proto_clean,
            addr=addr,
            port=port,
        )


@router.get("/flows")
def flows_list(
    request: Request,
    capture_id: str = Query(min_length=1, max_length=64),
    limit: int = Query(default=200, ge=1, le=1000),
    session: dict = Depends(_META),
) -> dict:
    with request.app.state.db.connect() as conn:
        return {"flows": packets_store.list_flows(conn, capture_id, limit=limit)}
