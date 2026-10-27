"""Capture engine: one live capture at a time, plus offline PCAP import.

Design (docs/DESIGN.md M2):
- dumpcap (preferred) or tcpdump write PcapNG ring files into
  captures/<id>/; disk usage stays bounded by the ring settings.
- A decoder thread decodes *closed* ring files with tshark and pushes packets
  into a bounded queue; a writer thread batches them into SQLite. If the queue
  is full, packets are dropped and `decode_drops` is incremented - drops are
  always visible, never silent.
- A monitor thread enforces: emergency halt (stops within ~1s), capture
  duration limits, unexpected source death, and byte counters.
- Stop preserves ring files, writes a sha256 manifest and audits the event.
- Import copies the source file, hashes it, decodes it in the background.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import secrets
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from ..analysis import sensitive as sensitive_mod
from ..config import AppConfig
from ..security.audit import append_event
from ..store import analysis as analysis_store
from ..store import evidence as evidence_store
from ..store import packets as packets_store
from ..store import websec as websec_store
from . import decode as decode_mod
from .pcapng import PcapngCounter
from .scope import ScopeError, bpf_filter, check_interface
from .sources import DumpcapSource, SourceError, TcpdumpSource

QUEUE_MAX = 100_000
BATCH = 500

logger = logging.getLogger("netherglass.engine")


class CaptureError(RuntimeError):
    def __init__(self, message: str, *, code: int = 409) -> None:
        super().__init__(message)
        self.code = code


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def make_capture_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"cap-{stamp}-{secrets.token_hex(2)}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class ActiveCapture:
    def __init__(self, capture_id: str, source, directory: Path) -> None:
        self.id = capture_id
        self.source = source
        self.dir = directory
        self.profile = "B"
        self.seen_secrets: set[str] = set()
        self.started_at = _utcnow()
        self.started_monotonic = time.monotonic()
        self.queue: queue.Queue = queue.Queue(maxsize=QUEUE_MAX)
        self.stop_flag = threading.Event()
        self.processed: set[str] = set()
        self.decode_drops = 0
        self.packets_decoded = 0
        self.files_decoded = 0
        self.last_decode_error: str | None = None
        self.status = "running"
        self.stop_reason: str | None = None
        self.decoder: threading.Thread | None = None
        self.writer: threading.Thread | None = None
        self.monitor: threading.Thread | None = None
        self.error: str | None = None
        self.pcap_counter = PcapngCounter()


class CaptureEngine:
    def __init__(
        self,
        config: AppConfig,
        db,
        emergency,
        *,
        poll_seconds: float = 0.5,
        tshark: str | None = None,
    ) -> None:
        self.config = config
        self.db = db
        self.emergency = emergency
        self.poll_seconds = poll_seconds
        self.tshark = tshark
        self.lock = threading.RLock()
        self.active: ActiveCapture | None = None
        self.patterns = self._load_patterns()
        self._storage_cache: tuple[float, int] | None = None

    # ------------------------------------------------------------ storage

    def _storage_bytes(self) -> int:
        now = time.monotonic()
        if self._storage_cache is not None and now - self._storage_cache[0] < 5.0:
            return self._storage_cache[1]
        total = 0
        for path in Path(self.config.data_dir).rglob("*"):
            if path.is_file():
                try:
                    total += path.stat().st_size
                except OSError:
                    continue
        self._storage_cache = (now, total)
        return total

    def storage_exceeded(self) -> bool:
        limit = self.config.scope.storage_limit_bytes
        if not limit or limit <= 0:
            return False
        return self._storage_bytes() >= limit

    def _load_patterns(self) -> list[dict]:
        try:
            return sensitive_mod.load_patterns(self.config.data_dir)
        except sensitive_mod.PatternError as exc:
            logger.warning("custom sensitive patterns ignored: %s", exc)
            return sensitive_mod.load_patterns(None)

    # ------------------------------------------------------------- status

    def status(self) -> dict:
        with self.lock:
            active = self.active
            if active is None:
                with self.db.connect() as conn:
                    recent = packets_store.list_captures(conn, limit=1)
                return {"active": False, "last_capture": recent[0] if recent else None}
            elapsed = time.monotonic() - active.started_monotonic
            source_counters = active.source.counters()
            counted = active.pcap_counter.update(self._ring_files(active))
            result = {
                "active": True,
                "capture_id": active.id,
                "interface": active.source.interface,
                "source": active.source.name,
                "started_at": active.started_at,
                "elapsed_seconds": round(elapsed, 1),
                "status": active.status,
                "queue_depth": active.queue.qsize(),
                "packets_decoded": active.packets_decoded,
                "decode_drops": active.decode_drops,
                "files_decoded": active.files_decoded,
                "bytes_written": _dir_bytes(active.dir),
                "last_error": active.error or active.last_decode_error
                or source_counters.get("last_error"),
                "stop_reason": active.stop_reason,
                **{k: v for k, v in source_counters.items() if k != "last_error"},
            }
            result["packets_captured"] = max(
                source_counters.get("packets_captured", 0), counted
            )
            return result

    # ---------------------------------------------------------- start/stop

    def start_live(
        self,
        interface: str,
        actor: str,
        *,
        bpf: str | None = None,
        chunk_seconds: int = 5,
    ) -> dict:
        with self.lock:
            if not self.emergency.capture_allowed():
                raise CaptureError(
                    "capture refused: emergency security stop is active", code=423
                )
            if self.active is not None:
                raise CaptureError(
                    f"capture already running: {self.active.id}", code=409
                )
            profile = self.config.profile
            if profile == "A":
                raise CaptureError(
                    "profile A stores metadata only and disables PCAP storage; "
                    "switch to profile B or C for live capture",
                    code=400,
                )
            known = {info.name for info in _interfaces()}
            if interface not in known:
                raise CaptureError(f"interface '{interface}' does not exist", code=400)
            try:
                check_interface(self.config.scope, interface)
                bpf_final, notes = bpf_filter(self.config.scope, extra=bpf)
            except ScopeError as exc:
                raise CaptureError(str(exc), code=400) from exc

            source_cls = self._select_source_class()
            capture_id = make_capture_id()
            directory = self.config.data_dir / "captures" / capture_id
            directory.mkdir(parents=True, exist_ok=False)
            os.chmod(directory, 0o700)
            source = source_cls(
                interface, directory, bpf=bpf_final, chunk_seconds=chunk_seconds
            )

            with self.db.connect() as conn:
                packets_store.create_capture(
                    conn,
                    capture_id=capture_id,
                    created_at=_utcnow(),
                    interface=interface,
                    profile=profile,
                    source=source.name,
                    bpf=bpf_final,
                )
                append_event(
                    conn,
                    actor=actor,
                    action="CAPTURE_STARTED",
                    target=capture_id,
                    details={
                        "interface": interface,
                        "source": source.name,
                        "profile": profile,
                        "bpf": bpf_final or "(none)",
                        "notes": "; ".join(notes),
                    },
                )

            active = ActiveCapture(capture_id, source, directory)
            active.profile = profile
            self.patterns = self._load_patterns()
            try:
                source.start()
            except SourceError as exc:
                with self.db.connect() as conn:
                    packets_store.update_capture(
                        conn, capture_id, status="error", error=str(exc)
                    )
                    append_event(
                        conn,
                        actor=actor,
                        action="CAPTURE_FAILED",
                        target=capture_id,
                        details={"error": str(exc)},
                    )
                raise CaptureError(str(exc), code=409) from exc

            self.active = active
            with self.db.connect() as conn:
                packets_store.update_capture(
                    conn,
                    capture_id,
                    status="running",
                    started_at=active.started_at,
                    bpf=bpf_final,
                )
            active.writer = threading.Thread(
                target=self._writer_loop, args=(active,), daemon=True
            )
            active.decoder = threading.Thread(
                target=self._decoder_loop, args=(active,), daemon=True
            )
            active.monitor = threading.Thread(
                target=self._monitor_loop, args=(active,), daemon=True
            )
            active.writer.start()
            active.decoder.start()
            active.monitor.start()
            return self.status()

    def stop(self, actor: str, reason: str | None = None) -> dict:
        with self.lock:
            active = self.active
            if active is None:
                raise CaptureError("no capture is running", code=409)
            return self._finalize(active, actor=actor, reason=reason)

    def _finalize(self, active: ActiveCapture, *, actor: str, reason: str | None) -> dict:
        active.status = "stopping"
        active.stop_flag.set()
        if reason:
            active.stop_reason = reason
        active.source.stop()
        if active.decoder:
            active.decoder.join(timeout=30)
        active.queue.put(None)
        if active.writer:
            active.writer.join(timeout=30)
        if active.monitor and active.monitor is not threading.current_thread():
            active.monitor.join(timeout=5)

        manifest = self._write_manifest(active)
        counters = active.source.counters()
        counted = active.pcap_counter.update(self._ring_files(active))
        captured = counters.get("packets_captured", 0) or counted
        final_status = "error" if active.error else "stopped"
        with self.db.connect() as conn:
            packets_store.update_capture(
                conn,
                active.id,
                status=final_status,
                stopped_at=_utcnow(),
                packets_captured=captured,
                packets_dropped=counters.get("packets_dropped", 0),
                decode_drops=active.decode_drops,
                bytes_written=manifest["total_bytes"],
                pcap_path=str(active.dir),
                error=active.error,
            )
            append_event(
                conn,
                actor=actor,
                action="CAPTURE_STOPPED",
                target=active.id,
                details={
                    "reason": reason or "operator stop",
                    "packets_captured": captured,
                    "packets_dropped": counters.get("packets_dropped", 0),
                    "packets_decoded": active.packets_decoded,
                    "decode_drops": active.decode_drops,
                    "files": len(manifest["files"]),
                },
            )
        self.active = None
        if active.packets_decoded:
            self._run_analysis(active.id, actor=actor)
        return {
            "capture_id": active.id,
            "status": final_status,
            "reason": reason or "operator stop",
            "packets_captured": captured,
            "packets_dropped": counters.get("packets_dropped", 0),
            "packets_decoded": active.packets_decoded,
            "decode_drops": active.decode_drops,
            "files": len(manifest["files"]),
            "total_bytes": manifest["total_bytes"],
        }

    # ------------------------------------------------------------ import

    def import_file(
        self, path: Path, actor: str, *, original_filename: str | None = None
    ) -> dict:
        if not self.emergency.capture_allowed():
            raise CaptureError(
                "import refused: emergency security stop is active", code=423
            )
        if self.storage_exceeded():
            raise CaptureError(
                "import refused: storage limit reached "
                f"({self.config.scope.storage_limit_bytes} bytes); free space "
                "or raise the limit first",
                code=507,
            )
        source_path = Path(path).expanduser()
        if not source_path.is_file():
            raise CaptureError(f"file not found: {source_path}", code=404)
        capture_id = make_capture_id()
        directory = self.config.data_dir / "captures" / capture_id
        src_dir = directory / "source"
        src_dir.mkdir(parents=True, exist_ok=False)
        os.chmod(directory, 0o700)
        os.chmod(src_dir, 0o700)
        name = original_filename or source_path.name
        safe_name = _sanitize_filename(name)
        target = src_dir / safe_name
        shutil.copy2(source_path, target)
        os.chmod(target, 0o600)
        digest = sha256_file(target)
        manifest = {
            "capture_id": capture_id,
            "source": "import",
            "created_at": _utcnow(),
            "original_filename": name,
            "sha256": digest,
            "size": target.stat().st_size,
        }
        (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        os.chmod(directory / "manifest.json", 0o600)

        with self.db.connect() as conn:
            packets_store.create_capture(
                conn,
                capture_id=capture_id,
                created_at=_utcnow(),
                interface=None,
                profile=self.config.profile,
                source="import",
                bpf=None,
                original_filename=name,
            )
            packets_store.update_capture(
                conn,
                capture_id,
                status="decoding",
                started_at=_utcnow(),
                stopped_at=_utcnow(),
                sha256=digest,
                bytes_written=target.stat().st_size,
                pcap_path=str(directory),
            )
            append_event(
                conn,
                actor=actor,
                action="PCAP_IMPORT_STARTED",
                target=capture_id,
                details={
                    "original_filename": name,
                    "sha256": digest,
                    "size": target.stat().st_size,
                },
            )
        self.patterns = self._load_patterns()
        thread = threading.Thread(
            target=self._import_job,
            args=(capture_id, directory, target, actor, self.config.profile),
            daemon=True,
        )
        thread.start()
        return {"capture_id": capture_id, "status": "decoding", "sha256": digest}

    def _import_job(
        self, capture_id: str, directory: Path, target: Path, actor: str, profile: str
    ) -> None:
        queue_: queue.Queue = queue.Queue(maxsize=QUEUE_MAX)
        state = {"decoded": 0, "drops": 0}
        writer = threading.Thread(
            target=self._writer_loop_raw,
            args=(capture_id, queue_, state),
            kwargs={"profile": profile},
            daemon=True,
        )
        writer.start()
        status = "ready"
        error: str | None = None
        saw_certificate = False
        try:
            for packet in decode_mod.iter_ek_packets(
                str(target), tshark=self.tshark, patterns=self.patterns
            ):
                packet["capture_id"] = capture_id
                tls = packet.get("tls")
                if tls and tls.get("kind") == "certificate":
                    saw_certificate = True
                try:
                    queue_.put_nowait(packet)
                except queue.Full:
                    state["drops"] += 1
        except decode_mod.DecodeError as exc:
            status, error = "error", str(exc)
        finally:
            queue_.put(None)
            writer.join(timeout=60)
        if saw_certificate:
            try:
                records = decode_mod.iter_tls_certificates(str(target), tshark=self.tshark)
                if records:
                    with self.db.connect() as conn:
                        analysis_store.apply_tls_certificates(conn, capture_id, records)
            except decode_mod.DecodeError as exc:
                error = error or str(exc)
        manifest = json.loads((directory / "manifest.json").read_text())
        manifest["decoded_packets"] = state["decoded"]
        manifest["decode_drops"] = state["drops"]
        (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        with self.db.connect() as conn:
            packets_store.update_capture(
                conn,
                capture_id,
                status=status,
                packets_captured=state["decoded"],
                packets_dropped=0,
                decode_drops=state["drops"],
                error=error,
            )
            append_event(
                conn,
                actor=actor,
                action="PCAP_IMPORT_COMPLETED" if status == "ready" else "PCAP_IMPORT_FAILED",
                target=capture_id,
                details={"decoded_packets": state["decoded"], "error": error},
            )
        if state["decoded"]:
            self._run_analysis(capture_id, actor=actor)

    # ----------------------------------------------------- internal loops

    def _select_source_class(self):
        if DumpcapSource.available():
            return DumpcapSource
        if TcpdumpSource.available():
            return TcpdumpSource
        dumpcap = shutil.which("dumpcap", mode=os.F_OK)
        if dumpcap and not os.access(dumpcap, os.X_OK):
            raise CaptureError(
                f"dumpcap is installed at {dumpcap} but not executable by this "
                "user; run: sudo usermod -aG wireshark $USER, then log out and "
                "back in (or use 'sg wireshark' / 'newgrp wireshark' for a shell)",
                code=409,
            )
        raise CaptureError(
            "no live capture source available: install wireshark-cli "
            "(dumpcap) or tcpdump",
            code=409,
        )

    def _writer_loop(self, active: ActiveCapture) -> None:
        flows: dict[tuple, dict] = {}
        batch: list[dict] = []
        while True:
            try:
                item = active.queue.get(timeout=0.25)
            except queue.Empty:
                if batch:
                    self._flush(
                        active.id,
                        batch,
                        flows,
                        profile=active.profile,
                        seen=active.seen_secrets,
                    )
                    batch.clear()
                    flows.clear()
                continue
            if item is None:
                break
            item["capture_id"] = active.id
            batch.append(item)
            key = (
                item.get("src"),
                item.get("dst"),
                (item.get("proto") or "unknown"),
                item.get("dport") or 0,
            )
            if key[0] and key[1]:
                flow = flows.setdefault(
                    key,
                    {"packets": 0, "bytes": 0, "first_ts": item.get("ts"), "last_ts": item.get("ts")},
                )
                flow["packets"] += 1
                flow["bytes"] += item.get("length") or 0
                ts = item.get("ts")
                if ts is not None:
                    flow["first_ts"] = ts if flow["first_ts"] is None else min(flow["first_ts"], ts)
                    flow["last_ts"] = ts if flow["last_ts"] is None else max(flow["last_ts"], ts)
            if len(batch) >= BATCH:
                self._flush(
                    active.id,
                    batch,
                    flows,
                    profile=active.profile,
                    seen=active.seen_secrets,
                )
                batch.clear()
                flows.clear()
        if batch:
            self._flush(
                active.id,
                batch,
                flows,
                profile=active.profile,
                seen=active.seen_secrets,
            )

    def _collect_sensitive(self, batch: list[dict]) -> list[dict]:
        items: list[dict] = []
        for row in batch:
            candidates = row.pop("_sensitive", None)
            if not candidates:
                continue
            http = row.get("http") or {}
            base = {
                "src": row.get("src"),
                "sport": row.get("sport"),
                "dst": row.get("dst"),
                "dport": row.get("dport"),
                "ts": row.get("ts"),
                "stream": row.get("stream"),
                "frame": row.get("num"),
                "protocol": row.get("app_proto") or row.get("proto"),
                "app_proto": row.get("app_proto"),
                "domain": http.get("host"),
                "host": http.get("host"),
                "http_method": http.get("method"),
                "path": http.get("path"),
                "transport_security": row.get("encryption"),
            }
            for candidate in candidates:
                items.append({**base, **candidate})
        return items

    def _seal_sensitive(
        self,
        conn,
        capture_id: str,
        items: list[dict],
        seen: set[str],
        profile: str,
    ) -> int:
        prepared: list[dict] = []
        for item in items:
            value = item.get("value") or ""
            key = hashlib.sha256(
                f"{item['type']}|{item.get('field')}|{item.get('stream')}|{value}".encode(
                    "utf-8"
                )
            ).hexdigest()
            if key in seen:
                continue
            seen.add(key)
            prepared.append(item)
        if not prepared:
            return 0
        created = evidence_store.seal_candidates(
            conn,
            capture_id,
            prepared,
            profile=profile,
            data_dir=self.config.data_dir,
        )
        if profile != "A":
            key = websec_store.fingerprint_key(self.config.data_dir / "keys")
            for item in prepared:
                websec_store.record_token(conn, capture_id, item, key)
        return len(created)

    def _flush(
        self,
        capture_id: str,
        batch: list[dict],
        flows: dict[tuple, dict],
        *,
        profile: str = "B",
        seen: set[str] | None = None,
    ) -> None:
        flow_rows = [
            {
                "capture_id": capture_id,
                "src": key[0],
                "dst": key[1],
                "proto": key[2],
                "dport": key[3],
                **value,
            }
            for key, value in flows.items()
        ]
        sensitive_items = self._collect_sensitive(batch)
        with self.db.connect() as conn:
            packets_store.insert_packets(conn, batch)
            if flow_rows:
                packets_store.upsert_flows(conn, flow_rows)
            analysis_store.record_batch(conn, capture_id, batch)
            if sensitive_items:
                self._seal_sensitive(
                    conn,
                    capture_id,
                    sensitive_items,
                    seen if seen is not None else set(),
                    profile,
                )

    def _run_analysis(self, capture_id: str, *, actor: str = "system") -> None:
        from ..analysis import rules as rules_mod

        try:
            with self.db.connect() as conn:
                count = rules_mod.run_and_store(
                    conn, capture_id, data_dir=self.config.data_dir
                )
                append_event(
                    conn,
                    actor=actor,
                    action="ANALYSIS_COMPLETED",
                    target=capture_id,
                    details={"findings": count},
                )
        except Exception as exc:
            logger.warning("analysis failed for %s: %s", capture_id, exc)

    def _writer_loop_raw(
        self, capture_id: str, q: queue.Queue, state: dict, *, profile: str = "B"
    ) -> None:
        flows: dict[tuple, dict] = {}
        batch: list[dict] = []
        seen: set[str] = set()
        while True:
            try:
                item = q.get(timeout=0.25)
            except queue.Empty:
                if batch:
                    self._flush(capture_id, batch, flows, profile=profile, seen=seen)
                    state["decoded"] += len(batch)
                    batch.clear()
                    flows.clear()
                continue
            if item is None:
                break
            batch.append(item)
            key = (
                item.get("src"),
                item.get("dst"),
                (item.get("proto") or "unknown"),
                item.get("dport") or 0,
            )
            if key[0] and key[1]:
                flow = flows.setdefault(
                    key,
                    {"packets": 0, "bytes": 0, "first_ts": item.get("ts"), "last_ts": item.get("ts")},
                )
                flow["packets"] += 1
                flow["bytes"] += item.get("length") or 0
            if len(batch) >= BATCH:
                self._flush(capture_id, batch, flows, profile=profile, seen=seen)
                state["decoded"] += len(batch)
                batch.clear()
                flows.clear()
        if batch:
            self._flush(capture_id, batch, flows, profile=profile, seen=seen)
            state["decoded"] += len(batch)

    def _decoder_loop(self, active: ActiveCapture) -> None:
        while True:
            if not active.stop_flag.is_set():
                self._decode_closed_files(active, only_closed=True)
                time.sleep(self.poll_seconds)
                continue
            self._decode_closed_files(active, only_closed=False)
            if not self._has_pending(active):
                break
            time.sleep(self.poll_seconds)

    def _ring_files(self, active: ActiveCapture) -> list[Path]:
        return sorted(
            active.dir.glob("*.pcapng"),
            key=lambda p: (p.stat().st_mtime if p.exists() else 0, p.name),
        )

    def _has_pending(self, active: ActiveCapture) -> bool:
        for path in self._ring_files(active):
            if str(path) in active.processed:
                continue
            try:
                if path.stat().st_size > 0:
                    return True
            except OSError:
                continue
        return False

    def _decode_closed_files(self, active: ActiveCapture, *, only_closed: bool) -> None:
        files = self._ring_files(active)
        selected = files[:-1] if only_closed else files
        for path in selected:
            key = str(path)
            if key in active.processed:
                continue
            if not path.exists() or path.stat().st_size == 0:
                continue
            saw_certificate = False
            try:
                for packet in decode_mod.iter_ek_packets(
                    str(path), tshark=self.tshark, patterns=self.patterns
                ):
                    active.packets_decoded += 1
                    tls = packet.get("tls")
                    if tls and tls.get("kind") == "certificate":
                        saw_certificate = True
                    try:
                        active.queue.put_nowait(packet)
                    except queue.Full:
                        active.decode_drops += 1
                if saw_certificate:
                    self._apply_certificate_pass(active, path)
                active.processed.add(key)
                active.files_decoded += 1
            except decode_mod.DecodeError as exc:
                active.last_decode_error = str(exc)
                active.processed.add(key)

    def _apply_certificate_pass(self, active: ActiveCapture, path: Path) -> None:
        try:
            records = decode_mod.iter_tls_certificates(str(path), tshark=self.tshark)
        except decode_mod.DecodeError as exc:
            active.last_decode_error = str(exc)
            return
        if records:
            with self.db.connect() as conn:
                analysis_store.apply_tls_certificates(conn, active.id, records)

    def _monitor_loop(self, active: ActiveCapture) -> None:
        max_seconds = self.config.scope.max_capture_seconds
        while not active.stop_flag.wait(self.poll_seconds):
            if self.emergency.capture_halt.is_set() or self.emergency.is_stopped():
                with self.lock:
                    if self.active is active:
                        self._finalize(
                            active,
                            actor="system",
                            reason="emergency security stop",
                        )
                return
            code = active.source.returncode()
            if code is not None:
                active.error = (
                    f"capture source exited unexpectedly (code {code}): "
                    f"{active.source.counters().get('last_error') or 'no detail'}"
                )
                with self.lock:
                    if self.active is active:
                        self._finalize(active, actor="system", reason="source failure")
                return
            if max_seconds and time.monotonic() - active.started_monotonic >= max_seconds:
                with self.lock:
                    if self.active is active:
                        self._finalize(
                            active,
                            actor="system",
                            reason=f"duration limit reached ({max_seconds}s)",
                        )
                return
            if self.storage_exceeded():
                with self.lock:
                    if self.active is active:
                        self._finalize(
                            active,
                            actor="system",
                            reason=(
                                "storage limit reached "
                                f"({self.config.scope.storage_limit_bytes} bytes)"
                            ),
                        )
                return

    def _write_manifest(self, active: ActiveCapture) -> dict:
        files = []
        total = 0
        for path in self._ring_files(active):
            if not path.exists():
                continue
            size = path.stat().st_size
            total += size
            files.append({"name": path.name, "size": size, "sha256": sha256_file(path)})
        manifest = {
            "capture_id": active.id,
            "source": active.source.name,
            "interface": active.source.interface,
            "created_at": active.started_at,
            "stopped_at": _utcnow(),
            "files": files,
            "total_bytes": total,
            "stop_reason": active.stop_reason,
        }
        try:
            (active.dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
            os.chmod(active.dir / "manifest.json", 0o600)
        except OSError:
            pass
        return manifest


def _dir_bytes(path: Path) -> int:
    total = 0
    try:
        for entry in path.rglob("*"):
            if entry.is_file():
                total += entry.stat().st_size
    except OSError:
        pass
    return total


def _sanitize_filename(name: str) -> str:
    cleaned = "".join(
        ch if ch.isalnum() or ch in "._-" else "_" for ch in Path(name).name
    )
    return cleaned[:120] or "capture.pcapng"


def _interfaces():
    from ..interfaces import discover_interfaces

    return discover_interfaces()
