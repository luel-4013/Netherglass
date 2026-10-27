"""M4 tests: sensitive-data collection, evidence vault, detection rules, API."""

import base64
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netherglass.analysis import rules as rules_mod
from netherglass.analysis import sensitive
from netherglass.api.app import create_app
from netherglass.capture.engine import CaptureEngine
from netherglass.config import AppConfig
from netherglass.emergency import EmergencyStop
from netherglass.security.audit import list_events
from netherglass.security.auth import create_user
from netherglass.store import evidence as evidence_store
from netherglass.store import findings as findings_store
from netherglass.store import packets as packets_store
from netherglass.store.db import Database

CAPTURE_ID = "cap-20261019-m4-0001"
SECRET = "hunter2-secret-value-xyz"


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    database = Database(tmp_path / "netherglass.db")
    database.migrate()
    with database.connect() as conn:
        packets_store.create_capture(
            conn,
            capture_id=CAPTURE_ID,
            created_at="2026-10-19T00:00:00+00:00",
            interface="lo",
            profile="C",
            source="import",
            bpf=None,
        )
    return database


def _candidate(**overrides) -> dict:
    candidate = {
        "type": "PASSWORD",
        "field": "form: password",
        "value": SECRET,
        "source": "http.form",
        "confidence": "OBSERVED",
        "meta": {"kind": "password"},
        "src": "10.0.0.5",
        "sport": 51234,
        "dst": "10.0.0.9",
        "dport": 80,
        "protocol": "http",
        "app_proto": "http",
        "host": "intranet.local",
        "path": "/login",
        "ts": 1700000000.0,
        "stream": "7",
        "frame": 42,
        "transport_security": "plaintext",
    }
    candidate.update(overrides)
    return candidate


# ----------------------------------------------------- sensitive collection


def test_collects_basic_auth_and_refines_jwt() -> None:
    basic = "Basic " + base64.b64encode(b"alice:s3cr3t").decode()
    items = sensitive.collect_candidates(
        {"http_http_authorization": basic}, {"app_proto": "http"}, []
    )
    assert items[0]["type"] == "BASIC_AUTH"
    assert items[0]["value"] == "alice:s3cr3t"
    assert items[0]["meta"]["username"] == "alice"

    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk"
    items = sensitive.collect_candidates(
        {"http_http_authorization": f"Bearer {jwt}"}, {"app_proto": "http"}
    )
    assert items[0]["type"] == "JWT"


def test_collects_cookies_query_and_form_fields() -> None:
    fields = {
        "http_http_cookie": "PHPSESSID=abc123def; theme=dark",
        "http_http_set_cookie": "auth=xyz; Path=/; HttpOnly; Secure; SameSite=Lax",
        "http_http_request_uri": "/reset?token=QUERYTOKEN",
        "urlencoded_form_key": "password",
        "urlencoded_form_value": "hunter2",
    }
    items = sensitive.collect_candidates(fields, {"app_proto": "http"}, [])
    by_field = {item["field"]: item for item in items}
    assert by_field["Cookie: PHPSESSID"]["type"] == "SESSION_COOKIE"
    assert by_field["Set-Cookie: auth"]["type"] == "AUTH_COOKIE"
    assert by_field["query: token"]["type"] == "ACCESS_TOKEN"
    assert by_field["form: password"]["type"] == "PASSWORD"
    meta = by_field["Set-Cookie: auth"]["meta"]
    assert meta["attributes"]["HttpOnly"] is True
    assert meta["attributes"]["SameSite"] == "Lax"
    assert by_field["Cookie: PHPSESSID"]["value"] == "abc123def"


def test_custom_patterns_from_rules_json(tmp_path: Path) -> None:
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(
        json.dumps(
            {
                "custom_patterns": [
                    {
                        "name": "corp",
                        "type": "CORP_TOKEN",
                        "regex": r"CORP-[A-Z0-9]{6}",
                    }
                ]
            }
        )
    )
    patterns = sensitive.load_patterns(tmp_path)
    items = sensitive.collect_candidates(
        {"http_http_authorization": "Bearer CORP-ABC123"},
        {"app_proto": "http"},
        patterns,
    )
    assert items[0]["type"] == "CORP_TOKEN"

    rules_path.write_text('{"custom_patterns": [{"regex": "("}]}')
    with pytest.raises(sensitive.PatternError):
        sensitive.load_patterns(tmp_path)


def test_ftp_and_non_http_apps() -> None:
    items = sensitive.collect_candidates(
        {"ftp_ftp_request_command": "PASS", "ftp_ftp_request_arg": "hunter2"},
        {"app_proto": "ftp"},
        [],
    )
    assert items[0]["type"] == "PASSWORD"
    items = sensitive.collect_candidates(
        {"http_http_authorization": "Basic Zm9vOmJhcg=="},
        {"app_proto": "tls"},
        [],
    )
    assert items == []


# --------------------------------------------------------------- vault


def test_seal_reveal_roundtrip_and_listing_hides_value(db: Database, tmp_path: Path) -> None:
    with db.connect() as conn:
        created = evidence_store.seal_candidates(
            conn, CAPTURE_ID, [_candidate()], profile="C", data_dir=tmp_path
        )
        listing = evidence_store.list_evidence(conn, CAPTURE_ID)
        row = evidence_store.get_evidence(conn, created[0])
        summary = evidence_store.summary(conn, CAPTURE_ID)
    assert row is not None
    assert row["status"] == "SEALED"
    assert row["sha256"]
    assert row["size"] > 0
    assert SECRET not in json.dumps(listing)
    assert listing["total"] == 1
    blob = evidence_store.reveal_value(tmp_path, row)
    assert blob["value"] == SECRET
    assert summary == [
        {
            "artifact_type": "PASSWORD",
            "count": 1,
            "sealed": 1,
            "metadata_only": 0,
        }
    ]


def test_metadata_only_profile_blocks_reveal(db: Database, tmp_path: Path) -> None:
    with db.connect() as conn:
        created = evidence_store.seal_candidates(
            conn, CAPTURE_ID, [_candidate()], profile="A", data_dir=tmp_path
        )
        row = evidence_store.get_evidence(conn, created[0])
    assert row["status"] == "METADATA_ONLY"
    assert row["sha256"] is None
    with pytest.raises(evidence_store.EvidenceError) as excinfo:
        evidence_store.reveal_value(tmp_path, row)
    assert excinfo.value.code == 409


# --------------------------------------------------------------- rules


def _seed_weak_tls(conn, *, version: str = "TLS1.0", cipher: str = "TLS_RSA_WITH_3DES_EDE_CBC_SHA") -> None:
    conn.execute(
        "INSERT INTO tls_sessions(capture_id, stream, client, server, sport, dport, "
        "version, cipher, first_ts, last_ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (CAPTURE_ID, "9", "10.0.0.5", "93.184.216.34", 51235, 443, version, cipher, 1.0, 2.0),
    )


def test_rules_find_plaintext_credentials_and_weak_tls(db: Database, tmp_path: Path) -> None:
    with db.connect() as conn:
        evidence_store.seal_candidates(
            conn, CAPTURE_ID, [_candidate()], profile="C", data_dir=tmp_path
        )
        _seed_weak_tls(conn)
        findings = rules_mod.run_rules(conn, CAPTURE_ID, data_dir=None)
    by_rule = {finding["rule_id"]: finding for finding in findings}
    assert by_rule["plaintext_credentials"]["severity"] == "CRITICAL"
    assert by_rule["plaintext_credentials"]["confidence"] == "OBSERVED"
    assert by_rule["plaintext_credentials"]["evidence_ids"]
    assert by_rule["weak_tls"]["severity"] == "HIGH"
    dumped = json.dumps(findings)
    assert SECRET not in dumped
    assert "3DES" in dumped


def test_rule_overrides_disable_and_rescore(db: Database, tmp_path: Path) -> None:
    (tmp_path / "rules.json").write_text(
        json.dumps(
            {
                "rules": {
                    "plaintext_credentials": {"enabled": False},
                    "weak_tls": {"severity": "LOW"},
                }
            }
        )
    )
    with db.connect() as conn:
        evidence_store.seal_candidates(
            conn, CAPTURE_ID, [_candidate()], profile="C", data_dir=tmp_path
        )
        _seed_weak_tls(conn)
        findings = rules_mod.run_rules(conn, CAPTURE_ID, data_dir=tmp_path)
    by_rule = {finding["rule_id"]: finding for finding in findings}
    assert "plaintext_credentials" not in by_rule
    assert by_rule["weak_tls"]["severity"] == "LOW"


def test_run_and_store_rebuilds_findings(db: Database, tmp_path: Path) -> None:
    with db.connect() as conn:
        evidence_store.seal_candidates(
            conn, CAPTURE_ID, [_candidate()], profile="C", data_dir=tmp_path
        )
        count = rules_mod.run_and_store(conn, CAPTURE_ID, data_dir=None)
        listing = findings_store.list_findings(conn, CAPTURE_ID)
        summary = findings_store.summary(conn, CAPTURE_ID)
        detail = findings_store.get_finding(conn, listing["findings"][0]["id"])
    assert count == listing["total"] >= 1
    assert summary["by_severity"]["CRITICAL"] >= 1
    assert detail["remediation"]
    assert detail["explanation"]


# --------------------------------------------------- engine flush sealing


def test_engine_flush_seals_and_deduplicates(db: Database, tmp_path: Path) -> None:
    config = AppConfig(data_dir=tmp_path)
    engine = CaptureEngine(config, db, EmergencyStop(db))
    row = {
        "capture_id": CAPTURE_ID,
        "num": 1,
        "ts": 1700000000.0,
        "src": "10.0.0.5",
        "dst": "10.0.0.9",
        "sport": 51234,
        "dport": 80,
        "proto": "tcp",
        "app_proto": "http",
        "encryption": "plaintext",
        "security": "insecure",
        "stream": "7",
        "length": 500,
        "http": {
            "kind": "request",
            "stream": "7",
            "method": "POST",
            "host": "intranet.local",
            "path": "/login",
            "query_names": [],
            "status": None,
            "user_agent": None,
            "content_type": None,
            "server": None,
            "version": "HTTP/1.1",
            "auth_scheme": None,
            "set_cookie_count": 0,
            "cookie_count": 0,
        },
        "_sensitive": [
            {
                "type": "PASSWORD",
                "field": "form: password",
                "value": SECRET,
                "source": "http.form",
                "confidence": "OBSERVED",
                "meta": {},
            }
        ],
    }
    seen: set[str] = set()
    engine._flush(CAPTURE_ID, [dict(row)], {}, profile="C", seen=seen)
    engine._flush(CAPTURE_ID, [dict(row)], {}, profile="C", seen=seen)
    with db.connect() as conn:
        listing = evidence_store.list_evidence(conn, CAPTURE_ID)
    assert listing["total"] == 1
    artifact = listing["artifacts"][0]
    assert artifact["transport_security"] == "plaintext"
    assert artifact["host"] == "intranet.local"
    assert SECRET not in json.dumps(listing)


# --------------------------------------------------------------- API


@pytest.fixture()
def client(tmp_path: Path):
    config = AppConfig(data_dir=tmp_path)
    app = create_app(config)
    with app.state.db.connect() as conn:
        create_user(conn, "testadmin", "admin-pw-123", "admin")
        create_user(conn, "testanalyst", "analyst-pw-123", "analyst")
        create_user(conn, "testauditor", "auditor-pw-123", "auditor")
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
            conn, CAPTURE_ID, [_candidate()], profile="C", data_dir=tmp_path
        )
    with TestClient(app) as test_client:
        yield test_client


def _login(client: TestClient, username: str, password: str) -> dict:
    response = client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_evidence_listing_respects_permissions(client: TestClient) -> None:
    _login(client, "testauditor", "auditor-pw-123")
    forbidden = client.get(f"/api/captures/{CAPTURE_ID}/evidence")
    assert forbidden.status_code == 403
    assert "VIEW_SENSITIVE_METADATA" in forbidden.json()["detail"]

    _login(client, "testanalyst", "analyst-pw-123")
    response = client.get(f"/api/captures/{CAPTURE_ID}/evidence")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 1
    assert SECRET not in response.text
    assert body["artifacts"][0]["status"] == "SEALED"
    assert body["summary"][0]["count"] == 1


def test_reveal_requires_value_permission_csrf_and_reason(client: TestClient) -> None:
    admin = _login(client, "testadmin", "admin-pw-123")
    with client.app.state.db.connect() as conn:
        evidence_id = evidence_store.list_evidence(
            conn, CAPTURE_ID
        )["artifacts"][0]["id"]

    _login(client, "testanalyst", "analyst-pw-123")
    denied = client.post(
        f"/api/evidence/{evidence_id}/reveal",
        json={"reason": "incident triage"},
        headers={"X-CSRF-Token": admin["csrf_token"]},
    )
    assert denied.status_code == 403
    assert "VIEW_SENSITIVE_VALUES" in denied.json()["detail"]

    admin = _login(client, "testadmin", "admin-pw-123")
    no_csrf = client.post(
        f"/api/evidence/{evidence_id}/reveal", json={"reason": "incident triage"}
    )
    assert no_csrf.status_code == 403

    no_reason = client.post(
        f"/api/evidence/{evidence_id}/reveal",
        json={"reason": ""},
        headers={"X-CSRF-Token": admin["csrf_token"]},
    )
    assert no_reason.status_code == 422

    revealed = client.post(
        f"/api/evidence/{evidence_id}/reveal",
        json={"reason": "incident triage"},
        headers={"X-CSRF-Token": admin["csrf_token"]},
    )
    assert revealed.status_code == 200, revealed.text
    body = revealed.json()
    assert body["value"] == SECRET
    assert body["auto_hide_seconds"] == 30
    with client.app.state.db.connect() as conn:
        events = list_events(conn)
    reveal_events = [e for e in events if e["action"] == "REVEAL_SENSITIVE_VALUE"]
    assert reveal_events
    assert reveal_events[0]["actor"] == "testadmin"
    assert reveal_events[0]["target"] == evidence_id


def test_reveal_blocked_during_emergency(client: TestClient) -> None:
    admin = _login(client, "testadmin", "admin-pw-123")
    headers = {"X-CSRF-Token": admin["csrf_token"]}
    with client.app.state.db.connect() as conn:
        evidence_id = evidence_store.list_evidence(
            conn, CAPTURE_ID
        )["artifacts"][0]["id"]
    stop = client.post(
        "/api/system/emergency-stop",
        json={"confirm": "EMERGENCY STOP"},
        headers=headers,
    )
    assert stop.status_code == 200, stop.text
    response = client.post(
        f"/api/evidence/{evidence_id}/reveal",
        json={"reason": "incident triage"},
        headers=headers,
    )
    assert response.status_code == 423


def test_findings_api_and_manual_analysis(client: TestClient) -> None:
    analyst = _login(client, "testanalyst", "analyst-pw-123")
    headers = {"X-CSRF-Token": analyst["csrf_token"]}
    analyzed = client.post(f"/api/captures/{CAPTURE_ID}/analyze", headers=headers)
    assert analyzed.status_code == 200, analyzed.text
    assert analyzed.json()["findings"] >= 1

    listing = client.get(f"/api/captures/{CAPTURE_ID}/findings")
    assert listing.status_code == 200, listing.text
    body = listing.json()
    assert body["total"] >= 1
    finding = body["findings"][0]
    assert finding["rule_id"] == "plaintext_credentials"
    assert finding["severity"] == "CRITICAL"
    assert SECRET not in listing.text

    detail = client.get(f"/api/findings/{finding['id']}")
    assert detail.status_code == 200
    assert detail.json()["remediation"]
    assert client.get("/api/findings/FND-999999").status_code == 404

    _login(client, "testauditor", "auditor-pw-123")
    assert client.get(f"/api/captures/{CAPTURE_ID}/findings").status_code == 200
    stats = client.get(f"/api/captures/{CAPTURE_ID}/stats")
    assert stats.status_code == 200
    assert stats.json()["sensitive_data"]["available"] is False
