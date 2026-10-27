"""M8 hardening tests (spec section 67): fuzzing, malformed input, high
volume, emergency interactions, API security, authz matrix, secret leakage,
tamper detection and best-effort secure deletion.

No production secrets are used anywhere in this file.
"""

from __future__ import annotations

import json
import shutil
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netherglass.analysis import protocols
from netherglass.analysis import sensitive as sensitive_mod
from netherglass.api.app import create_app
from netherglass.capture import decode as decode_mod
from netherglass.capture.engine import CaptureEngine, CaptureError
from netherglass.config import AppConfig
from netherglass.emergency import EmergencyStop
from netherglass.ingest import flowlogs as flowlogs_mod
from netherglass.ingest import k8s as k8s_mod
from netherglass.security.audit import list_events
from netherglass.security.auth import create_user
from netherglass.store import evidence as evidence_store
from netherglass.store import packets as packets_store
from netherglass.store.db import Database
from netherglass.testing_runner import ControlledTestRunner

from pcap_gen import dns_query_packet, tcp_syn_packet, write_pcap

HAS_TSHARK = shutil.which("tshark") is not None
CAPTURE_ID = "cap-20261019-m8-0001"

# ------------------------------------------------------------------ fuzzing


def test_fuzz_normalize_ek_never_raises() -> None:
    junk: list[object] = [
        None,
        42,
        [],
        {"a": None},
        {"a": {"b": {"c": [1, 2, [3, {"d": object()}]]}}},
        {"frame": {"frame_frame_protocols": 5}},
        {"ip": {"ip_ip_src": ["a", "b"]}},
        {"http": {"http_http_set_cookie": [None, 42, "a=b"]}},
        {"tcp": {"tcp_tcp_srcport": "not-a-port"}},
        {"~!@#": {"$%^": ["&*", {"()": 1.5, "": ""}]}},
        {"x" * 5000: [{"y" * 5000: "z" * 5000}]},
    ]
    for payload in junk:
        result = decode_mod.normalize_ek(payload)  # type: ignore[arg-type]
        assert result is None or isinstance(result, dict)


def test_fuzz_protocol_extractors_never_raise() -> None:
    junk_fields: list[dict] = [
        {},
        {"dns_dns_qry_name": None},
        {"dns_dns_qry_name": ["a", ["b", {"c": 1}]]},
        {"http_http_request_method": 5, "http_http_request_uri": None},
        {"http_http_response_code": ["200", "two hundred"]},
        {"tls_tls_handshake_extensions_server_name": {"nested": 1}},
        {"tls_tls_handshake_extensions_supported_version": [["1.2"], "1.3"]},
        {"tls_tls_handshake_certificate_validity_not_after": 999999999999},
    ]
    for fields in junk_fields:
        assert protocols.extract_dns(fields) is None or isinstance(
            protocols.extract_dns(fields), dict
        )
        for stream in (None, "0", 7, "not-a-stream"):
            extracted = protocols.extract_http(fields, stream)  # type: ignore[arg-type]
            assert extracted is None or isinstance(extracted, dict)
            tls = protocols.extract_tls(fields, stream)  # type: ignore[arg-type]
            assert tls is None or isinstance(tls, dict)


def test_fuzz_sensitive_collector_never_raises() -> None:
    junk_fields: list[dict] = [
        {},
        {"http_http_authorization": None},
        {"http_http_authorization": "Basic !!!not-base64!!!"},
        {"http_http_authorization": 42},
        {"http_http_cookie": [None, 5, "a", "sid=" + "x" * 100_000]},
        {"http_http_set_cookie": [["nested"], {"weird": True}]},
        {"http_http_user_agent": b"bytes-value"},
        {"http_http_request_uri": "?tok=" + "A" * 50_000},
    ]
    for fields in junk_fields:
        for packet in ({}, {"app_proto": "http"}, {"proto": "http"}):
            candidates = sensitive_mod.collect_candidates(fields, packet)
            assert isinstance(candidates, list)


def test_fuzz_flowlog_parsers_raise_clean_errors() -> None:
    bad_inputs = [
        ("aws", ""),
        ("aws", "version account-id\nonly-two-fields"),
        ("aws", "\x00\x01binary"),
        ("azure", "{not json"),
        ("azure", json.dumps({"records": "not-a-list"})),
        ("azure", json.dumps({"records": [{"properties": {"flows": [1, 2]}}]})),
        ("gcp", "["),
        ("gcp", json.dumps({"entries": [{"connection": "nope"}]})),
        ("generic-json", json.dumps([1, "two", None])),
        ("generic-csv", "\n\n\n"),
        ("no-such-format", "anything"),
    ]
    for fmt, text in bad_inputs:
        try:
            rows = flowlogs_mod.parse_flowlogs(text, fmt)
        except flowlogs_mod.FlowlogError:
            continue
        assert isinstance(rows, list)


def test_fuzz_detect_format_and_k8s_inventory(tmp_path: Path) -> None:
    weird = tmp_path / "weird.json"
    weird.write_bytes(b"\x00\xff\xfe{truncated")
    assert flowlogs_mod.detect_format(weird) in ("generic-json", "unknown")

    for payload in (
        {},
        {"items": None},
        {"items": [None, 5, "pod"]},
        {"items": [{"kind": "Pod", "metadata": None, "spec": "nope"}]},
        {"items": [{"kind": 7, "metadata": {"name": {"nested": 1}}}]},
    ):
        try:
            rows = k8s_mod.normalize_inventory(payload)  # type: ignore[arg-type]
        except k8s_mod.K8sError:
            continue
        assert isinstance(rows, list)


# ------------------------------------------------- malformed traffic handling


@pytest.mark.skipif(not HAS_TSHARK, reason="tshark not installed")
def test_truncated_and_malformed_frames_do_not_crash_import(tmp_path: Path) -> None:
    config = AppConfig(data_dir=tmp_path)
    db = Database(config.db_path())
    db.migrate()
    engine = CaptureEngine(config, db, EmergencyStop(db), poll_seconds=0.05)

    good = dns_query_packet("10.0.0.5", "10.0.0.53", "example.com")
    truncated_eth = good[:9]
    truncated_ip = good[:20]
    ip_len_lie = good[:16] + struct.pack("!H", 9999) + good[18:]
    tcp_dport_zero = tcp_syn_packet("10.0.0.9", "10.0.0.8", 443, 0)
    frames = [good, truncated_eth, truncated_ip, ip_len_lie, tcp_dport_zero]
    frames.extend(b"\x00" * 14 for _ in range(5))

    pcap = write_pcap(tmp_path / "malformed.pcap", frames)
    result = engine.import_file(pcap, actor="fuzzer")
    deadline = time.monotonic() + 20
    row = None
    while time.monotonic() < deadline:
        with db.connect() as conn:
            row = packets_store.get_capture(conn, result["capture_id"])
        if row and row["status"] != "decoding":
            break
        time.sleep(0.05)
    assert row is not None
    assert row["status"] == "ready", row.get("error")
    assert row["packets_captured"] >= 1  # good frame survives


@pytest.mark.skipif(not HAS_TSHARK, reason="tshark not installed")
def test_high_volume_import_bounded(tmp_path: Path) -> None:
    config = AppConfig(data_dir=tmp_path)
    db = Database(config.db_path())
    db.migrate()
    engine = CaptureEngine(config, db, EmergencyStop(db), poll_seconds=0.05)

    frames = [
        dns_query_packet(
            f"10.0.{i // 250}.{i % 250 + 1}", "10.0.0.53", f"host{i}.example.com"
        )
        for i in range(1500)
    ]
    pcap = write_pcap(tmp_path / "volume.pcap", frames)
    started = time.monotonic()
    result = engine.import_file(pcap, actor="loader")
    deadline = time.monotonic() + 90
    row = None
    while time.monotonic() < deadline:
        with db.connect() as conn:
            row = packets_store.get_capture(conn, result["capture_id"])
        if row and row["status"] != "decoding":
            break
        time.sleep(0.1)
    assert row is not None and row["status"] == "ready", (row or {}).get("error")
    assert row["packets_captured"] == 1500
    assert row["decode_drops"] == 0
    assert row["bytes_written"] > 0
    assert time.monotonic() - started < 90


def test_import_refused_under_emergency(tmp_path: Path) -> None:
    config = AppConfig(data_dir=tmp_path)
    db = Database(config.db_path())
    db.migrate()
    emergency = EmergencyStop(db)
    engine = CaptureEngine(config, db, emergency, poll_seconds=0.05)
    source = write_pcap(
        tmp_path / "x.pcap", [dns_query_packet("10.0.0.5", "10.0.0.53", "c.test")]
    )
    emergency.trigger(actor="tester", reason="m8 hardening drill")
    with pytest.raises(CaptureError) as excinfo:
        engine.import_file(source, actor="tester")
    assert excinfo.value.code == 423


def test_storage_pressure_boundaries(tmp_path: Path) -> None:
    config = AppConfig(data_dir=tmp_path)
    db = Database(config.db_path())
    db.migrate()
    engine = CaptureEngine(config, db, EmergencyStop(db), poll_seconds=0.05)
    (tmp_path / "big.bin").write_bytes(b"x" * 4096)

    config.scope.storage_limit_bytes = 0
    assert engine.storage_exceeded() is False  # 0 disables the limit
    engine._storage_cache = None

    config.scope.storage_limit_bytes = 2048
    assert engine.storage_exceeded() is True

    config.scope.storage_limit_bytes = 1024 * 1024
    engine._storage_cache = None
    assert engine.storage_exceeded() is False

    config.scope.storage_limit_bytes = 1024
    source = write_pcap(
        tmp_path / "over.pcap", [dns_query_packet("10.0.0.5", "10.0.0.53", "x.test")]
    )
    with pytest.raises(CaptureError) as excinfo:
        engine.import_file(source, actor="loader")
    assert excinfo.value.code == 507


# ----------------------------------------------------------- API security


@pytest.fixture()
def api_env(tmp_path: Path):
    config = AppConfig(data_dir=tmp_path)
    app = create_app(config)
    with app.state.db.connect() as conn:
        create_user(conn, "m8admin", "admin-pw-123", "admin")
        create_user(conn, "m8analyst", "analyst-pw-123", "analyst")
        create_user(conn, "m8auditor", "auditor-pw-123", "auditor")
        packets_store.create_capture(
            conn,
            capture_id=CAPTURE_ID,
            created_at="2026-10-19T00:00:00+00:00",
            interface="lo",
            profile="C",
            source="import",
            bpf=None,
        )
        evidence_store.seal_candidates(
            conn,
            CAPTURE_ID,
            [
                {
                    "type": "PASSWORD",
                    "field": "form: password",
                    "value": "m8-not-a-real-secret",
                    "source": "http.form",
                    "src": "10.0.0.5",
                    "dst": "10.0.0.9",
                    "host": "unit.test",
                    "protocol": "http",
                    "transport_security": "plaintext",
                    "ts": 1700000000.0,
                    "meta": {},
                }
            ],
            profile="C",
            data_dir=tmp_path,
        )
    with TestClient(app) as client:
        yield client, config, app


def _login(client: TestClient, username: str, password: str) -> dict:
    response = client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
    return response.json()


def _auth_headers(session: dict) -> dict:
    return {"X-CSRF-Token": session["csrf_token"]}


def test_security_headers_present(api_env) -> None:
    client, _, _ = api_env
    response = client.get("/api/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Cache-Control"] == "no-store"


def test_cross_origin_post_rejected(api_env) -> None:
    client, _, _ = api_env
    response = client.post(
        "/api/auth/login",
        json={"username": "m8admin", "password": "admin-pw-123"},
        headers={"Origin": "http://evil.example"},
    )
    assert response.status_code == 403


def test_unauthenticated_access_denied(api_env) -> None:
    client, _, _ = api_env
    for method, path in (
        ("get", "/api/captures"),
        ("get", f"/api/captures/{CAPTURE_ID}/evidence"),
        ("get", f"/api/captures/{CAPTURE_ID}/findings"),
        ("get", "/api/audit"),
        ("get", "/api/testing/scope"),
        ("get", "/api/system/status"),
    ):
        response = getattr(client, method)(path)
        assert response.status_code == 401, f"{path} -> {response.status_code}"


def test_permission_matrix_denies_low_roles(api_env) -> None:
    client, _, _ = api_env
    evidence_id = "EVD-000001"

    per_role = {
        "m8auditor": [
            ("post", "/api/capture/start", {"interface": "lo"}),
            ("get", f"/api/captures/{CAPTURE_ID}/evidence", None),
            ("post", "/api/system/emergency-stop", {"reason": "drill", "confirm": "EMERGENCY STOP"}),
        ],
        "m8analyst": [
            ("post", f"/api/evidence/{evidence_id}/reveal", {"reason": "audit"}),
            ("delete", f"/api/evidence/{evidence_id}", {"reason": "audit"}),
            ("post", "/api/system/emergency-recover", {"reason": "audit"}),
        ],
    }
    for username, password, denied in (
        ("m8auditor", "auditor-pw-123", per_role["m8auditor"]),
        ("m8analyst", "analyst-pw-123", per_role["m8analyst"]),
    ):
        session = _login(client, username, password)
        for method, path, body in denied:
            kwargs: dict = {"headers": _auth_headers(session)}
            if body is not None:
                kwargs["json"] = body
            response = client.request(method.upper(), path, **kwargs)
            assert response.status_code in (403, 404), (
                f"{username} {path} -> {response.status_code}"
            )


def test_evidence_delete_workflow(api_env) -> None:
    client, config, app = api_env
    admin = _login(client, "m8admin", "admin-pw-123")
    headers = _auth_headers(admin)
    blob = config.data_dir / "evidence" / "EVD-000001.ngv"
    assert blob.is_file()

    response = client.request(
        "DELETE",
        "/api/evidence/EVD-000001",
        json={"reason": "retention policy expired"},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "DELETED"
    assert not blob.exists()

    detail = client.get("/api/evidence/EVD-000001", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["status"] == "DELETED"

    reveal = client.post(
        "/api/evidence/EVD-000001/reveal",
        json={"reason": "should fail"},
        headers=headers,
    )
    assert reveal.status_code == 409  # value no longer retained

    again = client.request(
        "DELETE",
        "/api/evidence/EVD-000001",
        json={"reason": "double delete"},
        headers=headers,
    )
    assert again.status_code == 409

    with app.state.db.connect() as conn:
        events = list_events(conn, limit=50)
    actions = [event["action"] for event in events]
    assert "EVIDENCE_DELETED" in actions


def test_evidence_delete_refused_under_emergency(api_env) -> None:
    client, _, app = api_env
    admin = _login(client, "m8admin", "admin-pw-123")
    app.state.emergency.trigger(actor="m8admin", reason="hardening drill")
    response = client.request(
        "DELETE",
        "/api/evidence/EVD-000001",
        json={"reason": "must be refused"},
        headers=_auth_headers(admin),
    )
    assert response.status_code == 423


def test_evidence_tamper_detected(tmp_path: Path) -> None:
    config = AppConfig(data_dir=tmp_path)
    db = Database(config.db_path())
    db.migrate()
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
        ids = evidence_store.seal_candidates(
            conn,
            CAPTURE_ID,
            [
                {
                    "type": "PASSWORD",
                    "field": "form: password",
                    "value": "m8-tamper-check",
                    "source": "http.form",
                    "src": "10.0.0.5",
                    "dst": "10.0.0.9",
                    "host": "unit.test",
                    "protocol": "http",
                    "transport_security": "plaintext",
                    "ts": 1700000000.0,
                    "meta": {},
                }
            ],
            profile="C",
            data_dir=tmp_path,
        )
        assert ids == ["EVD-000001"]
        row = evidence_store.get_evidence(conn, "EVD-000001")
        assert row is not None
    blob = tmp_path / "evidence" / "EVD-000001.ngv"
    data = bytearray(blob.read_bytes())
    data[-1] ^= 0xFF
    blob.write_bytes(bytes(data))
    with db.connect() as conn:
        with pytest.raises(evidence_store.EvidenceError):
            evidence_store.reveal_value(tmp_path, row)


def test_dry_run_is_traffic_free_even_without_dns(tmp_path: Path) -> None:
    config = AppConfig(data_dir=tmp_path)
    db = Database(config.db_path())
    db.migrate()
    runner = ControlledTestRunner(config, db, EmergencyStop(db))
    (tmp_path / "testing_scope.json").write_text(
        json.dumps(
            {
                "assessments": [
                    {
                        "id": "M8-DRY",
                        "name": "dry run target",
                        "authorization_ref": "AUTH-M8-DRY",
                        "authorized_by": "unit test",
                        "domains": ["no-such-host.example"],
                        "cidrs": [],
                        "ports": [443],
                    }
                ]
            }
        )
    )
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
    test = runner.create_plan(
        actor="analyst",
        authorization_ref="AUTH-M8-DRY",
        target="no-such-host.example",
        test_type="TCP_CONNECT",
        port=443,
        artifact_id=None,
        case_id=None,
        dry_run=True,
        rate_limit_ms=100,
        max_requests=2,
        timeout_ms=1000,
        window_start=None,
        window_end=None,
    )
    runner.execute(test["id"], actor="admin")
    deadline = time.time() + 10
    done = runner.get(test["id"])
    while done["status"] == "EXECUTING" and time.time() < deadline:
        time.sleep(0.05)
        done = runner.get(test["id"])
    assert done["status"] == "DRY_RUN", done
    assert done["request_count"] >= 1
    assert all(row["outcome"] == "DRY_RUN" for row in done["results"])


# --------------------------------------- controlled-test secret echo defense


class _EchoHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        # hostile target: echoes the received credential into a response
        # header that the runner does summarize (set-cookie)
        self.send_response(200)
        self.send_header(
            "Set-Cookie",
            f"echo={self.headers.get('Cookie', '')} "
            f"auth={self.headers.get('Authorization', '')}",
        )
        self.end_headers()

    def log_message(self, *args) -> None:
        pass


def test_controlled_test_scrubs_echoed_secret(tmp_path: Path) -> None:
    secret = "M8-echo-not-a-real-secret"  # noqa: S105 - synthetic test value
    server = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        config = AppConfig(data_dir=tmp_path)
        db = Database(config.db_path())
        db.migrate()
        runner = ControlledTestRunner(config, db, EmergencyStop(db))
        (tmp_path / "testing_scope.json").write_text(
            json.dumps(
                {
                    "assessments": [
                        {
                            "id": "M8-ECHO",
                            "name": "echo target",
                            "authorization_ref": "AUTH-M8-ECHO",
                            "authorized_by": "unit test",
                            "domains": [],
                            "cidrs": ["127.0.0.0/8"],
                            "ports": [port],
                        }
                    ]
                }
            )
        )
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
                        "host": "echo.test",
                        "protocol": "http",
                        "transport_security": "plaintext",
                        "ts": 1700000000.0,
                        "meta": {},
                    }
                ],
                profile="C",
                data_dir=tmp_path,
            )
        evidence_id = created[0] if isinstance(created, list) else created["id"]

        test = runner.create_plan(
            actor="analyst",
            authorization_ref="AUTH-M8-ECHO",
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
        deadline = time.time() + 10
        done = runner.get(test["id"])
        while done["status"] in ("PLANNED", "EXECUTING") and time.time() < deadline:
            time.sleep(0.05)
            done = runner.get(test["id"])
        assert done["status"] == "COMPLETED", done

        results_text = json.dumps(done["results"])
        assert "[redacted]" in results_text
        assert secret not in results_text

        db_bytes = (config.data_dir / "netherglass.db").read_bytes()
        assert secret.encode() not in db_bytes
    finally:
        server.shutdown()


# ------------------------------------------------------- secret leakage scan


def test_secret_absent_from_disk_and_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "M8-not-a-real-secret-9f2e"  # noqa: S105 - synthetic test value
    config = AppConfig(data_dir=tmp_path)
    db = Database(config.db_path())
    db.migrate()
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
        from netherglass.store import analysis as analysis_store

        fields = {"http_http_authorization": f"Bearer {secret}"}
        packet = {
            "num": 1,
            "ts": 1700000000.0,
            "src": "10.0.0.5",
            "dst": "10.0.0.9",
            "sport": 50000,
            "dport": 80,
            "proto": "tcp",
            "app_proto": "http",
            "info": "POST /login",
            "_fields": fields,
        }
        analysis_store.record_batch(conn, CAPTURE_ID, [packet])

    secret_bytes = secret.encode()
    found_in: list[str] = []
    for path in config.data_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix == ".ngv":
            continue  # encrypted by design
        if secret_bytes in path.read_bytes():
            found_in.append(str(path))
    assert found_in == [], f"secret leaked into {found_in}"

    with db.connect() as conn:
        events_text = json.dumps(list_events(conn, limit=200))
    assert secret not in events_text
