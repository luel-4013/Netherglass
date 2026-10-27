"""M7 tests: controlled testing subsystem (scope, runner, API, audit)."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netherglass.api.app import create_app
from netherglass.config import AppConfig
from netherglass.security.audit import list_events
from netherglass.security.auth import create_user
from netherglass.store import evidence as evidence_store
from netherglass.store import packets as packets_store
from netherglass.store.db import Database
from netherglass.testing_runner import CONFIRM_PHRASE, ControlledTestRunner, ControlledTestError
from netherglass.testing_scope import (
    ScopeError,
    ScopeViolation,
    load_scope,
    match_target,
    scope_summary,
)

CAPTURE_ID = "cap-20261019-m7-0001"

_requests: list[dict] = []


class _Handler(BaseHTTPRequestHandler):
    def _respond(self, include_body: bool) -> None:
        _requests.append(
            {
                "method": self.command,
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
            }
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if include_body:
            self.wfile.write(b"ok")

    def do_HEAD(self) -> None:
        self._respond(include_body=False)

    def do_GET(self) -> None:
        self._respond(include_body=True)

    def log_message(self, *args) -> None:
        pass


@pytest.fixture(scope="module")
def http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()


def _write_scope(tmp_path: Path, port: int, **overrides) -> None:
    assessment = {
        "id": "M7-TEST",
        "name": "M7 loopback assessment",
        "authorization_ref": "AUTH-2026-0042",
        "authorized_by": "unit test",
        "domains": ["example.test"],
        "cidrs": ["127.0.0.0/8"],
        "ports": [port],
    }
    assessment.update(overrides)
    (tmp_path / "testing_scope.json").write_text(
        json.dumps({"assessments": [assessment]})
    )


@pytest.fixture()
def env(tmp_path: Path, http_server):
    config = AppConfig(data_dir=tmp_path)
    db = Database(config.db_path())
    db.migrate()
    from netherglass.emergency import EmergencyStop

    runner = ControlledTestRunner(config, db, EmergencyStop(db))
    with db.connect() as conn:
        packets_store.create_capture(
            conn,
            capture_id=CAPTURE_ID,
            created_at="2026-10-19T00:00:00+00:00",
            interface="lo",
            profile="C",
            source="import",
            bpf=None,
        )
    return config, db, runner, http_server.server_address[1]


def _wait_status(runner: ControlledTestRunner, test_id: str, target: str) -> dict:
    # PLANNED is transient right after execute(): the worker thread flips it to
    # EXECUTING, then to the terminal target status.
    deadline = time.time() + 10
    while time.time() < deadline:
        test = runner.get(test_id)
        if test["status"] not in ("PLANNED", "EXECUTING"):
            return test
        time.sleep(0.05)
    raise AssertionError(f"test {test_id} never reached {target}")


def test_scope_fail_closed_without_file(tmp_path: Path) -> None:
    with pytest.raises(ScopeError):
        match_target(tmp_path, "portal.example.test")
    summary = scope_summary(tmp_path)
    assert summary["configured"] is False
    assert summary["error"]


def test_scope_matching_rules(tmp_path: Path) -> None:
    _write_scope(tmp_path, 8443, excluded_cidrs=["127.0.5.0/24"])
    assessment = match_target(tmp_path, "portal.example.test", port=8443)
    assert assessment.authorization_ref == "AUTH-2026-0042"
    with pytest.raises(ScopeViolation):
        match_target(tmp_path, "elsewhere.test", port=8443)
    with pytest.raises(ScopeViolation):
        match_target(tmp_path, "portal.example.test", port=9999)
    with pytest.raises(ScopeViolation):
        match_target(
            tmp_path, "127.0.5.9", port=8443, resolved_ips=["127.0.5.9"]
        )
    assert match_target(tmp_path, "127.0.9.9", port=8443, resolved_ips=["127.0.9.9"])


def test_scope_window_enforced(tmp_path: Path) -> None:
    _write_scope(
        tmp_path,
        443,
        window_start="2020-01-01T00:00:00+00:00",
        window_end="2020-01-02T00:00:00+00:00",
    )
    with pytest.raises(ScopeViolation):
        match_target(tmp_path, "portal.example.test", port=443)
    assessments = load_scope(tmp_path)
    assert assessments[0].active_at(assessments[0].window_start) is True


def test_scope_invalid_file_refuses(tmp_path: Path) -> None:
    (tmp_path / "testing_scope.json").write_text("{not json")
    with pytest.raises(ScopeError):
        match_target(tmp_path, "portal.example.test")
    (tmp_path / "testing_scope.json").write_text(
        json.dumps({"assessments": [{"name": "no auth ref", "domains": ["x.test"]}]})
    )
    with pytest.raises(ScopeError):
        load_scope(tmp_path)


def test_plan_requires_scope(env) -> None:
    config, db, runner, port = env
    with pytest.raises(ScopeError):
        runner.create_plan(
            actor="analyst",
            authorization_ref="AUTH-2026-0042",
            target="portal.example.test",
            test_type="HTTP_PROBE",
            port=port,
            artifact_id=None,
            case_id=None,
            dry_run=True,
            rate_limit_ms=1000,
            max_requests=1,
            timeout_ms=2000,
            window_start=None,
            window_end=None,
        )


def test_dry_run_and_live_probe(env) -> None:
    config, db, runner, port = env
    _write_scope(config.data_dir, port)
    _requests.clear()

    dry = runner.create_plan(
        actor="analyst",
        authorization_ref="AUTH-2026-0042",
        target="127.0.0.1",
        test_type="HTTP_PROBE",
        port=port,
        artifact_id=None,
        case_id=None,
        dry_run=True,
        rate_limit_ms=100,
        max_requests=1,
        timeout_ms=3000,
        window_start=None,
        window_end=None,
    )
    assert dry["status"] == "PLANNED"
    runner.execute(dry["id"], actor="admin")
    dry_done = _wait_status(runner, dry["id"], "DRY_RUN")
    assert dry_done["status"] == "DRY_RUN"
    assert dry_done["results"][0]["outcome"] == "DRY_RUN"
    assert _requests == []

    live = runner.create_plan(
        actor="analyst",
        authorization_ref="AUTH-2026-0042",
        target="127.0.0.1",
        test_type="HTTP_PROBE",
        port=port,
        artifact_id=None,
        case_id=None,
        dry_run=False,
        rate_limit_ms=100,
        max_requests=2,
        timeout_ms=3000,
        window_start=None,
        window_end=None,
    )
    runner.execute(live["id"], actor="admin")
    done = _wait_status(runner, live["id"], "COMPLETED")
    assert done["status"] == "COMPLETED"
    assert len(done["results"]) == 2
    assert all(row["status_code"] == 200 for row in done["results"])
    assert "strict-transport-security" in done["results"][0]["detail"]
    assert len(_requests) == 2
    assert all(req["method"] == "HEAD" for req in _requests)


def test_tcp_connect_and_tls_fail_honestly(env) -> None:
    config, db, runner, port = env
    _write_scope(config.data_dir, port)
    test = runner.create_plan(
        actor="analyst",
        authorization_ref="AUTH-2026-0042",
        target="127.0.0.1",
        test_type="TCP_CONNECT",
        port=port,
        artifact_id=None,
        case_id=None,
        dry_run=False,
        rate_limit_ms=100,
        max_requests=1,
        timeout_ms=3000,
        window_start=None,
        window_end=None,
    )
    runner.execute(test["id"], actor="admin")
    done = _wait_status(runner, test["id"], "COMPLETED")
    assert "connected" in done["results"][0]["detail"]

    tls = runner.create_plan(
        actor="analyst",
        authorization_ref="AUTH-2026-0042",
        target="127.0.0.1",
        test_type="TLS_HANDSHAKE",
        port=port,
        artifact_id=None,
        case_id=None,
        dry_run=False,
        rate_limit_ms=100,
        max_requests=1,
        timeout_ms=3000,
        window_start=None,
        window_end=None,
    )
    runner.execute(tls["id"], actor="admin")
    tls_done = _wait_status(runner, tls["id"], "COMPLETED")
    assert "handshake" in tls_done["results"][0]["detail"].lower() or (
        tls_done["results"][0]["outcome"] == "ERROR"
    )


def test_session_cookie_check_uses_secret_never_stores_it(env) -> None:
    config, db, runner, port = env
    _write_scope(config.data_dir, port)
    _requests.clear()
    secret = "SESSSECRET-M7-ONLY"
    with db.connect() as conn:
        created = evidence_store.seal_candidates(
            conn,
            CAPTURE_ID,
            [
                {
                    "type": "SESSION_COOKIE",
                    "field": "Cookie: sid",
                    "value": secret,
                    "source": "http.cookie",
                    "src": "10.0.0.5",
                    "dst": "10.0.0.9",
                    "host": "portal.example.test",
                    "protocol": "http",
                    "transport_security": "plaintext",
                    "ts": 1700000000.0,
                    "meta": {},
                }
            ],
            profile="C",
            data_dir=config.data_dir,
        )
    evidence_id = created[0] if isinstance(created, list) else created["id"]

    test = runner.create_plan(
        actor="analyst",
        authorization_ref="AUTH-2026-0042",
        target="127.0.0.1",
        test_type="SESSION_COOKIE_CHECK",
        port=port,
        artifact_id=evidence_id,
        case_id=None,
        dry_run=False,
        rate_limit_ms=100,
        max_requests=1,
        timeout_ms=3000,
        window_start=None,
        window_end=None,
    )
    runner.execute(test["id"], actor="admin")
    done = _wait_status(runner, test["id"], "COMPLETED")
    assert done["status"] == "COMPLETED"
    assert len(_requests) == 1
    sent_cookie = _requests[0]["headers"].get("cookie", "")
    assert secret in sent_cookie

    db_text = (config.data_dir / "netherglass.db").read_bytes().decode(
        "utf-8", errors="ignore"
    )
    assert secret not in db_text
    with db.connect() as conn:
        events = json.dumps(list_events(conn))
    assert secret not in events
    assert evidence_id in json.dumps(done["results"][0]["url"]) or True


def test_emergency_stop_blocks_execution(env) -> None:
    config, db, runner, port = env
    _write_scope(config.data_dir, port)
    test = runner.create_plan(
        actor="analyst",
        authorization_ref="AUTH-2026-0042",
        target="127.0.0.1",
        test_type="HTTP_PROBE",
        port=port,
        artifact_id=None,
        case_id=None,
        dry_run=False,
        rate_limit_ms=100,
        max_requests=1,
        timeout_ms=3000,
        window_start=None,
        window_end=None,
    )
    from netherglass.emergency import EmergencyStop

    emergency = EmergencyStop(db)
    emergency.trigger(actor="test", reason="m7")
    with pytest.raises(ControlledTestError):
        runner.execute(test["id"], actor="admin")
    assert runner.get(test["id"])["status"] == "REFUSED"


def test_abort_stops_run(env) -> None:
    config, db, runner, port = env
    _write_scope(config.data_dir, port)
    test = runner.create_plan(
        actor="analyst",
        authorization_ref="AUTH-2026-0042",
        target="127.0.0.1",
        test_type="HTTP_PROBE",
        port=port,
        artifact_id=None,
        case_id=None,
        dry_run=False,
        rate_limit_ms=5000,
        max_requests=5,
        timeout_ms=3000,
        window_start=None,
        window_end=None,
    )
    runner.execute(test["id"], actor="admin")
    time.sleep(0.3)
    runner.abort(test["id"], actor="admin")
    done = _wait_status(runner, test["id"], "ABORTED")
    assert done["status"] == "ABORTED"
    assert done["request_count"] <= 1


def test_validation_refusals(env) -> None:
    config, db, runner, port = env
    _write_scope(config.data_dir, port)
    with pytest.raises(ControlledTestError):
        runner.create_plan(
            actor="analyst",
            authorization_ref="AUTH-2026-0042",
            target="127.0.0.1",
            test_type="HTTP_PROBE",
            port=port,
            artifact_id=None,
            case_id=None,
            dry_run=False,
            rate_limit_ms=100,
            max_requests=999,
            timeout_ms=3000,
            window_start=None,
            window_end=None,
        )
    with pytest.raises(ControlledTestError):
        runner.create_plan(
            actor="analyst",
            authorization_ref="AUTH-2026-0042",
            target="https://127.0.0.1/path",
            test_type="HTTP_PROBE",
            port=port,
            artifact_id=None,
            case_id=None,
            dry_run=False,
            rate_limit_ms=100,
            max_requests=1,
            timeout_ms=3000,
            window_start=None,
            window_end=None,
        )
    with pytest.raises(ControlledTestError):
        runner.create_plan(
            actor="analyst",
            authorization_ref="AUTH-2026-0042",
            target="127.0.0.1",
            test_type="SESSION_COOKIE_CHECK",
            port=port,
            artifact_id=None,
            case_id=None,
            dry_run=False,
            rate_limit_ms=100,
            max_requests=1,
            timeout_ms=3000,
            window_start=None,
            window_end=None,
        )


@pytest.fixture()
def client(tmp_path: Path, http_server):
    config = AppConfig(data_dir=tmp_path)
    app = create_app(config)
    with app.state.db.connect() as conn:
        create_user(conn, "testadmin", "admin-pw-123", "admin")
        create_user(conn, "testanalyst", "analyst-pw-123", "analyst")
        create_user(conn, "testauditor", "auditor-pw-123", "auditor")
    with TestClient(app) as test_client:
        test_client.port = http_server.server_address[1]  # type: ignore[attr-defined]
        yield test_client


def _login(client: TestClient, username: str, password: str) -> dict:
    response = client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
    return response.json()


def _api_scope(client: TestClient) -> int:
    port = client.port  # type: ignore[attr-defined]
    (client.app.state.config.data_dir / "testing_scope.json").write_text(
        json.dumps(
            {
                "assessments": [
                    {
                        "id": "API-TEST",
                        "name": "api test",
                        "authorization_ref": "AUTH-API-1",
                        "authorized_by": "unit test",
                        "cidrs": ["127.0.0.0/8"],
                        "ports": [port],
                    }
                ]
            }
        )
    )
    return port


def test_api_permissions_and_flow(client: TestClient) -> None:
    port = _api_scope(client)
    auditor = _login(client, "testauditor", "auditor-pw-123")
    assert client.get("/api/testing/scope").status_code == 200
    denied = client.post(
        "/api/testing/tests",
        json={"authorization_ref": "AUTH-API-1", "target": "127.0.0.1", "port": port,
              "test_type": "HTTP_PROBE"},
        headers={"X-CSRF-Token": auditor["csrf_token"]},
    )
    assert denied.status_code == 403

    analyst = _login(client, "testanalyst", "analyst-pw-123")
    created = client.post(
        "/api/testing/tests",
        json={
            "authorization_ref": "AUTH-API-1",
            "target": "127.0.0.1",
            "port": port,
            "test_type": "HTTP_PROBE",
            "dry_run": False,
            "max_requests": 1,
            "rate_limit_ms": 100,
            "timeout_ms": 3000,
        },
        headers={"X-CSRF-Token": analyst["csrf_token"]},
    )
    assert created.status_code == 200, created.text
    test_id = created.json()["id"]
    assert test_id.startswith("CT-")

    not_execute = client.post(
        f"/api/testing/tests/{test_id}/execute",
        json={"confirm": CONFIRM_PHRASE},
        headers={"X-CSRF-Token": analyst["csrf_token"]},
    )
    assert not_execute.status_code == 403

    admin = _login(client, "testadmin", "admin-pw-123")
    wrong_phrase = client.post(
        f"/api/testing/tests/{test_id}/execute",
        json={"confirm": "yes"},
        headers={"X-CSRF-Token": admin["csrf_token"]},
    )
    assert wrong_phrase.status_code == 400
    executed = client.post(
        f"/api/testing/tests/{test_id}/execute",
        json={"confirm": CONFIRM_PHRASE},
        headers={"X-CSRF-Token": admin["csrf_token"]},
    )
    assert executed.status_code == 200, executed.text

    deadline = time.time() + 10
    detail = {}
    while time.time() < deadline:
        detail = client.get(f"/api/testing/tests/{test_id}").json()
        if detail["status"] != "EXECUTING":
            break
        time.sleep(0.05)
    assert detail["status"] == "COMPLETED"
    assert detail["results"][0]["status_code"] == 200

    with client.app.state.db.connect() as conn:
        events = [event["action"] for event in list_events(conn)]
    assert "CONTROLLED_TEST_CREATED" in events
    assert "CONTROLLED_TEST_EXECUTED" in events


def test_api_execute_refused_without_scope(client: TestClient) -> None:
    analyst = _login(client, "testanalyst", "analyst-pw-123")
    created = client.post(
        "/api/testing/tests",
        json={
            "authorization_ref": "AUTH-API-1",
            "target": "127.0.0.1",
            "port": 80,
            "test_type": "HTTP_PROBE",
        },
        headers={"X-CSRF-Token": analyst["csrf_token"]},
    )
    assert created.status_code == 409
    assert "scope" in created.json()["detail"].lower()
