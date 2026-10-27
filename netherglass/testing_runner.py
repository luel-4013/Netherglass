"""Controlled security testing runner (spec sections 50-56).

Hard safety rules:
- separate subsystem: never touches the capture pipeline;
- every run requires an authorization reference matching an active scope
  assessment at execution time (fail closed);
- dry-run is the default; live execution needs EXECUTE_CONTROLLED_TEST plus an
  explicit confirmation phrase at the API layer;
- bounded: max_requests, per-request timeout, minimum interval between
  requests, hard wall-clock cap;
- the Emergency Security Stop overrides everything: runs refuse to start and
  abort between requests;
- captured secret values are unsealed in memory only for cookie/token checks
  and are never written to results, audit details or logs (the evidence ID is
  referenced instead).
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from urllib import error as urlerror
from urllib import request as urlrequest

from .emergency import EmergencyStop
from .store import counters
from .store import evidence as evidence_store
from .store.db import Database
from .testing_scope import ScopeError, ScopeViolation, match_target

RUN_TEST_TYPES = ("TCP_CONNECT", "TLS_HANDSHAKE", "HTTP_PROBE", "SESSION_COOKIE_CHECK", "BEARER_TOKEN_CHECK")
ARTIFACT_TEST_TYPES = {"SESSION_COOKIE_CHECK", "BEARER_TOKEN_CHECK"}
MAX_WALL_SECONDS = 300.0
CONFIRM_PHRASE = "AUTHORIZE TEST"


class ControlledTestError(ValueError):
    """Controlled-testing misuse (fail closed)."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _now_ts() -> float:
    return time.monotonic()


class ControlledTestRunner:
    def __init__(self, config, db: Database, emergency: EmergencyStop) -> None:
        self.config = config
        self.db = db
        self.emergency = emergency
        self._abort: set[str] = set()
        self._lock = threading.Lock()
        self._threads: dict[str, threading.Thread] = {}

    # ------------------------------------------------------------- lifecycle

    def create_plan(
        self,
        *,
        actor: str,
        authorization_ref: str,
        target: str,
        test_type: str,
        port: int | None,
        artifact_id: str | None,
        case_id: str | None,
        dry_run: bool,
        rate_limit_ms: int,
        max_requests: int,
        timeout_ms: int,
        window_start: str | None,
        window_end: str | None,
    ) -> dict:
        test_type = str(test_type or "").strip().upper()
        if test_type not in RUN_TEST_TYPES:
            raise ControlledTestError(f"unsupported test type: {test_type!r}")
        target = str(target or "").strip().lower().rstrip(".")
        if not target or len(target) > 253:
            raise ControlledTestError("target must be a hostname or IP address")
        if any(ch in target for ch in " /\\?#"):
            raise ControlledTestError("target must be a bare hostname or IP (no scheme/path)")
        if test_type in ARTIFACT_TEST_TYPES and not artifact_id:
            raise ControlledTestError(f"{test_type} requires an artifact (evidence id)")
        if test_type not in ARTIFACT_TEST_TYPES and artifact_id:
            raise ControlledTestError(f"artifact is not used by {test_type}")
        if not (1 <= max_requests <= 50):
            raise ControlledTestError("max_requests must be between 1 and 50")
        if not (100 <= rate_limit_ms <= 60_000):
            raise ControlledTestError("rate_limit_ms must be between 100 and 60000")
        if not (200 <= timeout_ms <= 30_000):
            raise ControlledTestError("timeout_ms must be between 200 and 30000")
        if test_type in ("HTTP_PROBE", "SESSION_COOKIE_CHECK", "BEARER_TOKEN_CHECK"):
            port = port or 443
        elif port is None:
            port = 80 if test_type == "TCP_CONNECT" else 443

        resolved_ips: list[str] = []
        try:
            resolved_ips = _resolve(target)
        except OSError:
            resolved_ips = []
        assessment = match_target(
            self.config.data_dir,
            target,
            port=port,
            resolved_ips=resolved_ips,
        )

        with self.db.connect() as conn:
            if artifact_id:
                row = conn.execute(
                    "SELECT id, artifact_type, status FROM evidence WHERE id = ?",
                    (artifact_id,),
                ).fetchone()
                if row is None:
                    raise ControlledTestError(f"evidence not found: {artifact_id}")
                if row["status"] not in ("SEALED",):
                    raise ControlledTestError(
                        f"evidence {artifact_id} is {row['status']}; only SEALED "
                        "artifacts can be used in controlled tests"
                    )
                artifact_type = row["artifact_type"]
            else:
                artifact_type = None
            test_id = counters.next_id(conn, "controlled_test", "CT")
            conn.execute(
                """
                INSERT INTO controlled_tests(id, created_by, created_at,
                    authorization_ref, assessment_id, target, domain, port,
                    protocol, test_type, artifact_type, artifact_id, case_id,
                    status, dry_run, rate_limit_ms, max_requests, timeout_ms,
                    window_start, window_end)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PLANNED', ?, ?, ?,
                        ?, ?, ?)
                """,
                (
                    test_id,
                    actor,
                    _utcnow(),
                    assessment.authorization_ref,
                    assessment.id,
                    target,
                    target,
                    port,
                    "https" if port == 443 else ("http" if port == 80 else "tcp"),
                    test_type,
                    artifact_type,
                    artifact_id,
                    case_id,
                    1 if dry_run else 0,
                    rate_limit_ms,
                    max_requests,
                    timeout_ms,
                    window_start,
                    window_end,
                ),
            )
        return self.get(test_id)

    def get(self, test_id: str) -> dict:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM controlled_tests WHERE id = ?", (test_id,)
            ).fetchone()
            if row is None:
                raise ControlledTestError(f"test not found: {test_id}")
            results = [
                dict(item)
                for item in conn.execute(
                    "SELECT * FROM controlled_test_results WHERE test_id = ? "
                    "ORDER BY seq",
                    (test_id,),
                ).fetchall()
            ]
        test = dict(row)
        test["results"] = results
        return test

    def list_tests(self, *, limit: int = 100) -> list[dict]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, created_by, created_at, authorization_ref, target,
                       port, protocol, test_type, artifact_type, artifact_id,
                       case_id, status, dry_run, request_count, started_at,
                       ended_at, error
                FROM controlled_tests ORDER BY created_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def execute(self, test_id: str, *, actor: str) -> dict:
        if self.emergency.is_stopped():
            self._refuse(test_id, "emergency stop active")
            raise ControlledTestError("controlled tests are disabled during emergency stop")
        with self._lock:
            if test_id in self._threads and self._threads[test_id].is_alive():
                raise ControlledTestError("test is already executing")
            test = self.get(test_id)
            if test["status"] in ("EXECUTING",):
                raise ControlledTestError("test is already executing")
            if test["status"] not in ("PLANNED", "DRY_RUN", "COMPLETED", "FAILED", "ABORTED"):
                raise ControlledTestError(f"test cannot run from status {test['status']}")
            self._abort.discard(test_id)
            thread = threading.Thread(
                target=self._run,
                args=(test_id, actor),
                daemon=True,
                name=f"controlled-test-{test_id}",
            )
            self._threads[test_id] = thread
            thread.start()
        return self.get(test_id)

    def abort(self, test_id: str, *, actor: str) -> dict:
        with self._lock:
            self._abort.add(test_id)
        test = self.get(test_id)
        if test["status"] not in ("EXECUTING",):
            return test
        return self.get(test_id)

    def _refuse(self, test_id: str, reason: str) -> None:
        with self.db.connect() as conn:
            conn.execute(
                "UPDATE controlled_tests SET status = 'REFUSED', error = ?, "
                "ended_at = ? WHERE id = ?",
                (reason, _utcnow(), test_id),
            )

    # ------------------------------------------------------------- execution

    def _run(self, test_id: str, actor: str) -> None:
        try:
            with self.db.connect() as conn:
                conn.execute(
                    "UPDATE controlled_tests SET status = 'EXECUTING', "
                    "started_at = ?, error = NULL, request_count = 0 WHERE id = ?",
                    (_utcnow(), test_id),
                )
                conn.execute(
                    "DELETE FROM controlled_test_results WHERE test_id = ?",
                    (test_id,),
                )
            test = self.get(test_id)
            self._execute_requests(test, actor)
        except Exception as exc:  # fail closed, record the failure
            self._finish(test_id, "FAILED", str(exc))

    def _finish(self, test_id: str, status: str, error: str | None = None) -> None:
        with self.db.connect() as conn:
            conn.execute(
                "UPDATE controlled_tests SET status = ?, ended_at = ?, error = ? "
                "WHERE id = ?",
                (status, _utcnow(), error, test_id),
            )

    def _record(
        self,
        test_id: str,
        seq: int,
        *,
        request_kind: str,
        method: str | None,
        url: str | None,
        status_code: int | None,
        outcome: str,
        detail: str | None,
        duration_ms: int | None,
        dry_run: bool,
    ) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO controlled_test_results(test_id, seq, ts,
                    request_kind, method, url, status_code, outcome, detail,
                    duration_ms, dry_run)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    test_id,
                    seq,
                    _utcnow(),
                    request_kind,
                    method,
                    url,
                    status_code,
                    outcome,
                    detail,
                    duration_ms,
                    1 if dry_run else 0,
                ),
            )
            conn.execute(
                "UPDATE controlled_tests SET request_count = ? WHERE id = ?",
                (seq, test_id),
            )

    def _aborted(self, test_id: str) -> bool:
        with self._lock:
            return test_id in self._abort

    def _execute_requests(self, test: dict, actor: str) -> None:
        test_id = test["id"]
        dry_run = bool(test["dry_run"])
        max_requests = int(test["max_requests"])
        timeout = int(test["timeout_ms"]) / 1000.0
        rate = int(test["rate_limit_ms"]) / 1000.0
        wall_start = _now_ts()

        resolved: list[str] = []
        if not dry_run:
            # dry runs must not touch the network at all, not even DNS; this
            # also means hostname targets authorized only via CIDR cannot be
            # dry-run (fail closed) because resolution is what links them
            try:
                resolved = _resolve(test["target"])
            except OSError:
                resolved = []
                if test["test_type"] == "TCP_CONNECT":
                    self._record(
                        test_id, 1,
                        request_kind="DNS",
                        method=None, url=test["target"],
                        status_code=None, outcome="ERROR",
                        detail="DNS resolution failed",
                        duration_ms=None, dry_run=dry_run,
                    )
                    self._finish(test_id, "FAILED", "DNS resolution failed")
                    return

        try:
            match_target(
                self.config.data_dir,
                test["target"],
                port=test["port"],
                resolved_ips=resolved,
            )
        except (ScopeError, ScopeViolation) as exc:
            self._record(
                test_id, 1,
                request_kind="SCOPE",
                method=None, url=test["target"],
                status_code=None, outcome="REFUSED",
                detail=str(exc),
                duration_ms=None, dry_run=dry_run,
            )
            self._finish(test_id, "REFUSED", str(exc))
            return

        scheme = "https" if test["port"] == 443 else "http"
        base_url = f"{scheme}://{test['target']}:{test['port']}"
        for seq in range(1, max_requests + 1):
            if self.emergency.is_stopped():
                self._finish(test_id, "ABORTED", "emergency stop")
                return
            if self._aborted(test_id):
                self._finish(test_id, "ABORTED", "operator abort")
                return
            if _now_ts() - wall_start > MAX_WALL_SECONDS:
                self._finish(test_id, "ABORTED", "wall-clock cap reached")
                return
            if seq > 1:
                if not self._sleep_interruptible(test_id, rate):
                    self._finish(test_id, "ABORTED", "operator abort")
                    return
            started = _now_ts()
            try:
                outcome = self._one_request(test, seq, base_url, timeout, dry_run,
                                            resolved)
            except Exception as exc:
                self._record(
                    test_id, seq,
                    request_kind=test["test_type"],
                    method=outcome_method(test["test_type"]),
                    url=base_url,
                    status_code=None, outcome="ERROR",
                    detail=f"{type(exc).__name__}: {exc}"[:300],
                    duration_ms=int((_now_ts() - started) * 1000),
                    dry_run=dry_run,
                )
                continue
            kind, status_code, detail = outcome
            self._record(
                test_id, seq,
                request_kind=kind,
                method=outcome_method(test["test_type"]),
                url=base_url,
                status_code=status_code,
                outcome="DRY_RUN" if dry_run else "OK",
                detail=detail,
                duration_ms=int((_now_ts() - started) * 1000),
                dry_run=dry_run,
            )
            if dry_run:
                break
        status = "DRY_RUN" if dry_run else "COMPLETED"
        self._finish(test_id, status, None)

    def _sleep_interruptible(self, test_id: str, seconds: float) -> bool:
        deadline = _now_ts() + seconds
        while _now_ts() < deadline:
            if self._aborted(test_id) or self.emergency.is_stopped():
                return False
            time.sleep(min(0.1, max(0.0, deadline - _now_ts())))
        return True

    def _one_request(
        self,
        test: dict,
        seq: int,
        base_url: str,
        timeout: float,
        dry_run: bool,
        resolved: list[str],
    ) -> tuple[str, int | None, str | None]:
        test_type = test["test_type"]
        if test_type == "TCP_CONNECT":
            if dry_run:
                return (
                    "TCP_CONNECT",
                    None,
                    f"dry run: would open TCP connection to {test['target']}:"
                    f"{test['port']}",
                )
            _, latency = _tcp_connect(test["target"], test["port"], timeout)
            return ("TCP_CONNECT", None, f"connected in {latency:.0f}ms")
        if test_type == "TLS_HANDSHAKE":
            if dry_run:
                return (
                    "TLS_HANDSHAKE",
                    None,
                    "dry run: would perform TLS handshake and record version/"
                    "cipher/certificate validity",
                )
            info = _tls_handshake(test["target"], test["port"], timeout)
            return ("TLS_HANDSHAKE", None, info)
        if test_type == "HTTP_PROBE":
            if dry_run:
                return (
                    "HTTP_PROBE",
                    None,
                    f"dry run: would send HEAD {base_url}/ and record status + "
                    "security headers",
                )
            status_code, detail = _http_request(
                base_url, "/", method="HEAD", timeout=timeout, headers={}
            )
            return ("HTTP_PROBE", status_code, detail)
        if test_type in ARTIFACT_TEST_TYPES:
            secret, label = self._load_artifact(test)
            if test_type == "SESSION_COOKIE_CHECK":
                header_name, header_value = "Cookie", f"{label}={secret}"
            else:
                header_name, header_value = "Authorization", f"Bearer {secret}"
            if dry_run:
                return (
                    test_type,
                    None,
                    f"dry run: would send one request with the {header_name} "
                    f"header derived from evidence {test['artifact_id']} (value "
                    "never logged; 1 request)",
                )
            status_code, detail = _http_request(
                base_url,
                "/",
                method="GET",
                timeout=timeout,
                headers={header_name: header_value},
            )
            # a hostile or debug target could echo the sent credential back in
            # a response header; never let that reach results/audit storage
            if secret:
                detail = detail.replace(secret, "[redacted]")
                detail = detail.replace(header_value, "[redacted]")
            return (test_type, status_code, detail)
        raise ControlledTestError(f"unsupported test type: {test_type}")

    def _load_artifact(self, test: dict) -> tuple[str, str]:
        evidence_id = test.get("artifact_id")
        if not evidence_id:
            raise ControlledTestError("artifact evidence id missing")
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM evidence WHERE id = ?", (evidence_id,)
            ).fetchone()
        if row is None:
            raise ControlledTestError(f"evidence not found: {evidence_id}")
        artifact = dict(row)
        if artifact["status"] != "SEALED":
            raise ControlledTestError(f"evidence {evidence_id} is not sealed")
        revealed = evidence_store.reveal_value(self.config.data_dir, artifact)
        value = revealed.get("value")
        if value is None:
            raise ControlledTestError(f"evidence {evidence_id} has no retained value")
        label = ""
        field = artifact.get("field") or ""
        if field.startswith("Cookie: "):
            label = field.split(":", 1)[1].strip()
        elif field.startswith("Set-Cookie: "):
            label = field.split(":", 1)[1].strip().split(";")[0].strip()
        return str(value), label or "session"


def outcome_method(test_type: str) -> str | None:
    if test_type in ("HTTP_PROBE", "SESSION_COOKIE_CHECK", "BEARER_TOKEN_CHECK"):
        return "HEAD" if test_type == "HTTP_PROBE" else "GET"
    return None


def _resolve(host: str) -> list[str]:
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def _tcp_connect(host: str, port: int, timeout: float) -> tuple[bool, float]:
    started = _now_ts()
    with socket.create_connection((host, port), timeout=timeout):
        pass
    return True, (_now_ts() - started) * 1000


def _tls_handshake(host: str, port: int, timeout: float) -> str:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            version = tls.version() or "unknown"
            cipher = (tls.cipher() or ("unknown",))[0]
            cert = tls.getpeercert() or {}
            not_after = cert.get("notAfter", "unavailable")
            return f"TLS {version}, cipher {cipher}, cert notAfter {not_after}"


_MAX_HEADER_SUMMARY = 240


def _http_request(
    base_url: str,
    path: str,
    *,
    method: str,
    timeout: float,
    headers: dict[str, str],
) -> tuple[int, str]:
    request = urlrequest.Request(
        base_url + path,
        method=method,
        headers={"User-Agent": "netherglass-controlled-test/1.0", **headers},
    )
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with urlrequest.urlopen(request, timeout=timeout, context=context) as response:
            status_code = response.status
            security_headers = {
                key.lower(): value
                for key, value in response.headers.items()
                if key.lower()
                in (
                    "strict-transport-security",
                    "content-security-policy",
                    "x-content-type-options",
                    "x-frame-options",
                    "referrer-policy",
                    "set-cookie",
                    "server",
                )
            }
            summary_bits = [
                f"{key}={value[:60]}" for key, value in sorted(security_headers.items())
            ]
            summary = "; ".join(summary_bits)[:_MAX_HEADER_SUMMARY] or "no security headers"
            return status_code, summary
    except urlerror.HTTPError as exc:
        return exc.code, f"HTTP {exc.code} (response received)"
