"""M5 tests: web security analysis, cases, timeline, graph, reports."""

import base64
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netherglass.analysis import protocols
from netherglass.analysis import report as report_mod
from netherglass.analysis import rules as rules_mod
from netherglass.analysis import sensitive
from netherglass.api.app import create_app
from netherglass.config import AppConfig
from netherglass.security.audit import list_events
from netherglass.security.auth import create_user
from netherglass.store import analysis as analysis_store
from netherglass.store import cases as cases_store
from netherglass.store import evidence as evidence_store
from netherglass.store import graph as graph_store
from netherglass.store import packets as packets_store
from netherglass.store import timeline as timeline_store
from netherglass.store import websec as websec_store
from netherglass.store.db import Database

CAPTURE_ID = "cap-20261019-m5-0001"


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


def _http_packet(**overrides) -> dict:
    packet = {
        "num": 10,
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
        "length": 400,
        "http_host": "portal.example",
        "http_method": "GET",
        "http": {
            "kind": "request",
            "stream": "7",
            "method": "GET",
            "host": "portal.example",
            "path": "/login",
            "query_names": [],
            "status": None,
            "user_agent": "curl/8",
            "content_type": None,
            "server": None,
            "version": "HTTP/1.1",
            "auth_scheme": None,
            "set_cookie_count": 0,
            "cookie_count": 1,
            "set_cookies": [],
            "request_cookie_names": ["sid"],
            "security_headers": {},
        },
    }
    packet.update(overrides)
    return packet


def _response_packet(**overrides) -> dict:
    packet = _http_packet(
        num=11,
        ts=1700000001.0,
        src="10.0.0.9",
        dst="10.0.0.5",
        sport=80,
        dport=51234,
    )
    packet["http"] = {
        "kind": "response",
        "stream": "7",
        "method": None,
        "host": None,
        "path": None,
        "query_names": [],
        "status": 200,
        "user_agent": None,
        "content_type": "text/html",
        "server": "nginx",
        "version": None,
        "auth_scheme": None,
        "set_cookie_count": 1,
        "cookie_count": 0,
        "set_cookies": [
            {
                "name": "sid",
                "secure": False,
                "http_only": False,
                "same_site": None,
                "domain": None,
                "path": "/",
                "max_age": 60 * 60 * 24 * 90,
            }
        ],
        "request_cookie_names": [],
        "security_headers": {
            "hsts": False,
            "csp": False,
            "x_content_type_options": False,
            "x_frame_options": False,
            "referrer_policy": False,
            "permissions_policy": False,
            "cache_control": "no-store",
            "server": "nginx",
        },
    }
    packet.update(overrides)
    return packet


# ------------------------------------------------------ header extraction


def test_parse_security_headers_and_cookies() -> None:
    headers = protocols.parse_security_headers(
        [
            "Strict-Transport-Security: max-age=31536000\r\n",
            "Content-Security-Policy: default-src 'self'\r\n",
            "X-Frame-Options: DENY\r\n",
            "Cache-Control: no-store\r\n",
            "Server: nginx/1.25\r\n",
        ]
    )
    assert headers["hsts"] is True
    assert headers["csp"] is True
    assert headers["x_frame_options"] is True
    assert headers["x_content_type_options"] is False
    assert headers["cache_control"] == "no-store"
    assert headers["server"] == "nginx/1.25"

    cookie = protocols.parse_set_cookie_metadata(
        "sid=SECRETVALUE; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600"
    )
    assert cookie is not None
    assert cookie["name"] == "sid"
    assert cookie["secure"] is True
    assert cookie["http_only"] is True
    assert cookie["same_site"] == "Strict"
    assert cookie["max_age"] == 3600
    assert "SECRETVALUE" not in json.dumps(cookie)


def test_extract_http_records_response_metadata_without_values() -> None:
    fields = {
        "http_http_response": "1",
        "http_http_response_code": "200",
        "http_http_set_cookie": "auth=TOPSECRET; Secure; SameSite=Lax",
        "http_http_response_line": [
            "Set-Cookie: auth=TOPSECRET; Secure; SameSite=Lax\r\n",
            "X-Content-Type-Options: nosniff\r\n",
        ],
    }
    http = protocols.extract_http(fields, stream="3")
    assert http is not None
    assert http["kind"] == "response"
    assert http["security_headers"]["x_content_type_options"] is True
    assert http["set_cookies"][0]["name"] == "auth"
    assert http["set_cookies"][0]["same_site"] == "Lax"
    assert "TOPSECRET" not in json.dumps(http)


def test_jwt_metadata_extraction() -> None:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","kid":"k1","typ":"JWT"}').rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps(
            {"sub": "alice", "iss": "https://idp.example", "iat": 1700000000, "exp": 1700003600}
        ).encode()
    ).rstrip(b"=")
    token = f"{header.decode()}.{payload.decode()}.signaturepart"
    metadata = sensitive.jwt_metadata(token)
    assert metadata is not None
    assert metadata["alg"] == "HS256"
    assert metadata["kid"] == "k1"
    assert metadata["claims"]["sub"] == "alice"
    assert metadata["claims"]["exp"] == 1700003600

    items = sensitive.collect_candidates(
        {"http_http_authorization": f"Bearer {token}"}, {"app_proto": "http"}, []
    )
    assert items[0]["type"] == "JWT"
    assert items[0]["meta"]["jwt"]["alg"] == "HS256"


# ------------------------------------------------------------- web tables


def test_http_recording_builds_cookie_header_and_token_tables(
    db: Database, tmp_path: Path
) -> None:
    key = websec_store.fingerprint_key(tmp_path / "keys")
    with db.connect() as conn:
        analysis_store.record_batch(conn, CAPTURE_ID, [_http_packet()])
        analysis_store.record_batch(conn, CAPTURE_ID, [_response_packet()])
        cookies = websec_store.list_cookies(conn, CAPTURE_ID)["cookies"]
        headers = websec_store.list_headers(conn, CAPTURE_ID)["hosts"]

        item = {
            "type": "SESSION_COOKIE",
            "field": "Cookie: sid",
            "value": "abc123",
            "host": "portal.example",
            "src": "10.0.0.5",
            "ts": 1700000000.0,
            "transport_security": "plaintext",
            "meta": {"cookie_name": "sid"},
        }
        fingerprint = websec_store.record_token(conn, CAPTURE_ID, item, key)
        assert fingerprint
        websec_store.record_token(conn, CAPTURE_ID, item, key)
        tokens = websec_store.list_tokens(conn, CAPTURE_ID)["tokens"]
    by_name = {cookie["name"]: cookie for cookie in cookies}
    assert by_name["sid"]["kind"] == "SESSION_COOKIE"
    assert by_name["sid"]["set_observed"] == 1
    assert by_name["sid"]["plaintext"] == 1
    assert by_name["sid"]["max_age"] == 60 * 60 * 24 * 90
    assert headers[0]["host"] == "portal.example"
    assert headers[0]["responses"] == 1
    assert headers[0]["hsts"] == 0
    assert headers[0]["cache_control"] == "no-store"
    assert len(tokens) == 1
    assert tokens[0]["seen_count"] == 2
    assert "abc123" not in json.dumps(tokens)


def test_app_inventory_and_data_flows(db: Database, tmp_path: Path) -> None:
    with db.connect() as conn:
        analysis_store.record_batch(conn, CAPTURE_ID, [_http_packet()])
        analysis_store.record_batch(conn, CAPTURE_ID, [_response_packet()])
        conn.execute(
            "INSERT INTO dns_events(capture_id, ts, client, server, qname, qtype, "
            "rcode, answers, matched) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                CAPTURE_ID,
                1699999999.0,
                "10.0.0.5",
                "10.0.0.1",
                "portal.example",
                "A",
                "NOERROR",
                json.dumps(["10.0.0.9"]),
                1,
            ),
        )
        conn.execute(
            "INSERT INTO tls_sessions(capture_id, stream, client, server, sport, "
            "dport, version, sni, cipher, security, first_ts, last_ts) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                CAPTURE_ID,
                "8",
                "10.0.0.5",
                "10.0.0.9",
                51000,
                443,
                "TLS1.3",
                "portal.example",
                "TLS_AES_128_GCM_SHA256",
                "good",
                1699999990.0,
                1699999995.0,
            ),
        )
        evidence_store.seal_candidates(
            conn,
            CAPTURE_ID,
            [
                {
                    "type": "PASSWORD",
                    "field": "form: password",
                    "value": "hunter2",
                    "source": "http.form",
                    "src": "10.0.0.5",
                    "dst": "93.184.216.34",
                    "host": "portal.example",
                    "protocol": "http",
                    "transport_security": "plaintext",
                    "ts": 1700000000.0,
                    "meta": {},
                }
            ],
            profile="C",
            data_dir=tmp_path,
        )
        inventory = websec_store.app_inventory(conn, CAPTURE_ID)
        flows = websec_store.data_flows(conn, CAPTURE_ID)
    app = inventory["applications"][0]
    assert app["host"] == "portal.example"
    assert app["http_requests"] == 1
    assert app["http_responses"] == 1
    assert app["ips"] == ["10.0.0.9"]
    assert app["tls"][0]["version"] == "TLS1.3"
    assert app["endpoints"] == ["GET /login"]
    flow = flows["flows"][0]
    assert flow["artifact_type"] == "PASSWORD"
    assert flow["destination_internal"] is False
    assert flow["transport_risk"] == "HIGH"
    assert "hunter2" not in json.dumps(flows)


# ------------------------------------------------------------------ rules


def test_web_rules_produce_findings(db: Database, tmp_path: Path) -> None:
    with db.connect() as conn:
        analysis_store.record_batch(conn, CAPTURE_ID, [_http_packet()])
        analysis_store.record_batch(conn, CAPTURE_ID, [_response_packet()])
        key = websec_store.fingerprint_key(tmp_path / "keys")
        websec_store.record_token(
            conn,
            CAPTURE_ID,
            {
                "type": "SESSION_COOKIE",
                "field": "Cookie: sid",
                "value": "abc123",
                "host": "portal.example",
                "src": "10.0.0.5",
                "ts": 1700000000.0,
                "transport_security": "plaintext",
                "meta": {"cookie_name": "sid"},
            },
            key,
        )
        websec_store.record_token(
            conn,
            CAPTURE_ID,
            {
                "type": "SESSION_COOKIE",
                "field": "Cookie: sid",
                "value": "abc123",
                "host": "other.example",
                "src": "10.0.0.6",
                "ts": 1700000002.0,
                "transport_security": "encrypted",
                "meta": {"cookie_name": "sid"},
            },
            key,
        )
        evidence_store.seal_candidates(
            conn,
            CAPTURE_ID,
            [
                {
                    "type": "PASSWORD",
                    "field": "form: password",
                    "value": "hunter2",
                    "source": "http.form",
                    "src": "10.0.0.5",
                    "dst": "93.184.216.34",
                    "host": "portal.example",
                    "protocol": "http",
                    "transport_security": "plaintext",
                    "ts": 1700000000.0,
                    "meta": {},
                }
            ],
            profile="C",
            data_dir=tmp_path,
        )
        findings = rules_mod.run_rules(conn, CAPTURE_ID, data_dir=None)
    by_rule: dict[str, list[dict]] = {}
    for finding in findings:
        by_rule.setdefault(finding["rule_id"], []).append(finding)
    assert "cookie_attributes" in by_rule
    assert by_rule["cookie_attributes"][0]["severity"] == "HIGH"
    assert "cookie_over_plaintext" in by_rule
    assert "missing_security_headers" in by_rule
    assert "token_boundary" in by_rule
    assert "http_not_https" in by_rule
    assert "sensitive_to_external" in by_rule
    assert by_rule["sensitive_to_external"][0]["severity"] == "HIGH"
    dumped = json.dumps(findings)
    assert "hunter2" not in dumped
    assert "abc123" not in dumped


def test_long_lived_jwt_rule(db: Database) -> None:
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO web_tokens(capture_id, fingerprint, kind, name, alg, "
            "claims, hosts, clients, plaintext, seen_count, first_ts, last_ts) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                CAPTURE_ID,
                "f" * 64,
                "JWT",
                "Bearer",
                "HS256",
                json.dumps({"iat": 1600000000, "exp": 1900000000}),
                json.dumps(["portal.example"]),
                json.dumps(["10.0.0.5"]),
                0,
                1,
                1600000000.0,
                1600000000.0,
            ),
        )
        findings = rules_mod.run_rules(conn, CAPTURE_ID, data_dir=None)
    by_rule = {finding["rule_id"]: finding for finding in findings}
    assert "long_lived_token" in by_rule
    assert "day lifetime" in by_rule["long_lived_token"]["explanation"]


# ------------------------------------------------------------- cases/timeline


def test_case_lifecycle(db: Database) -> None:
    with db.connect() as conn:
        case = cases_store.create_case(
            conn, title="Credential exposure", summary="login leak", created_by="analyst1"
        )
        assert case["id"].startswith("CS-")
        cases_store.add_item(
            conn,
            case["id"],
            item_type="note",
            item_id="note-1",
            capture_id=CAPTURE_ID,
            note="observed on portal",
            added_by="analyst1",
        )
        updated = cases_store.update_case(conn, case["id"], status="CLOSED")
        listed = cases_store.list_cases(conn)
        timeline = cases_store.case_timeline(conn, case["id"])
    assert updated["status"] == "CLOSED"
    assert updated["closed_at"]
    assert listed[0]["item_count"] == 1
    assert timeline[0]["kind"] == "note"
    with pytest.raises(cases_store.CaseError):
        cases_store.create_case(conn, title="x", summary="", created_by="a")


def test_timeline_merges_sources_and_filters(db: Database, tmp_path: Path) -> None:
    with db.connect() as conn:
        analysis_store.record_batch(conn, CAPTURE_ID, [_http_packet()])
        analysis_store.record_batch(conn, CAPTURE_ID, [_response_packet()])
        conn.execute(
            "INSERT INTO dns_events(capture_id, ts, client, server, qname, qtype, "
            "rcode, matched) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (CAPTURE_ID, 1700000000.5, "10.0.0.5", "10.0.0.1", "portal.example", "A", "NOERROR", 0),
        )
        evidence_store.seal_candidates(
            conn,
            CAPTURE_ID,
            [
                {
                    "type": "PASSWORD",
                    "field": "form: password",
                    "value": "hunter2",
                    "source": "http.form",
                    "src": "10.0.0.5",
                    "dst": "10.0.0.9",
                    "host": "portal.example",
                    "protocol": "http",
                    "transport_security": "plaintext",
                    "ts": 1700000000.0,
                    "meta": {},
                }
            ],
            profile="C",
            data_dir=tmp_path,
        )
        rules_mod.run_and_store(conn, CAPTURE_ID, data_dir=None)
        everything = timeline_store.build_timeline(conn, CAPTURE_ID)
        dns_only = timeline_store.build_timeline(conn, CAPTURE_ID, kinds={"dns"})
        by_host = timeline_store.build_timeline(conn, CAPTURE_ID, host="portal")
        severe = timeline_store.build_timeline(conn, CAPTURE_ID, severity="CRITICAL")
    kinds = {event["kind"] for event in everything["events"]}
    assert {"http", "dns", "finding", "evidence"} <= kinds
    assert all(event["kind"] == "dns" for event in dns_only["events"])
    assert by_host["events"]
    assert all(event["severity"] == "CRITICAL" for event in severe["events"])
    assert "hunter2" not in json.dumps(everything)


def test_graphs(db: Database, tmp_path: Path) -> None:
    with db.connect() as conn:
        analysis_store.record_batch(conn, CAPTURE_ID, [_http_packet()])
        analysis_store.record_batch(conn, CAPTURE_ID, [_response_packet()])
        conn.execute(
            "INSERT INTO flows(capture_id, src, dst, proto, dport, packets, bytes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (CAPTURE_ID, "10.0.0.5", "10.0.0.9", "tcp", 80, 4, 1200),
        )
        conn.execute(
            "INSERT INTO dns_events(capture_id, ts, client, server, qname, qtype, "
            "rcode, answers, matched) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                CAPTURE_ID,
                1699999999.0,
                "10.0.0.5",
                "10.0.0.1",
                "portal.example",
                "A",
                "NOERROR",
                json.dumps(["10.0.0.9"]),
                1,
            ),
        )
        rules_mod.run_and_store(conn, CAPTURE_ID, data_dir=None)
        network = graph_store.network_graph(conn, CAPTURE_ID)
        connection = graph_store.connection_graph(conn, CAPTURE_ID)
    assert {node["id"] for node in network["nodes"]} >= {"10.0.0.5", "10.0.0.9"}
    assert network["edges"][0]["kind"] == "flow"
    kinds = {node["kind"] for node in connection["nodes"]}
    assert {"host", "domain", "http"} <= kinds
    assert any(edge["kind"] == "dns" for edge in connection["edges"])


# ----------------------------------------------------------------- reports


def test_standard_report_omits_values_and_restricted_includes_them(
    db: Database, tmp_path: Path
) -> None:
    with db.connect() as conn:
        evidence_store.seal_candidates(
            conn,
            CAPTURE_ID,
            [
                {
                    "type": "PASSWORD",
                    "field": "form: password",
                    "value": "hunter2",
                    "source": "http.form",
                    "src": "10.0.0.5",
                    "dst": "10.0.0.9",
                    "host": "portal.example",
                    "protocol": "http",
                    "transport_security": "plaintext",
                    "ts": 1700000000.0,
                    "meta": {},
                }
            ],
            profile="C",
            data_dir=tmp_path,
        )
        rules_mod.run_and_store(conn, CAPTURE_ID, data_dir=None)
        standard = report_mod.build_report(
            conn, CAPTURE_ID, data_dir=tmp_path, generated_by="analyst1"
        )
        restricted = report_mod.build_report(
            conn,
            CAPTURE_ID,
            data_dir=tmp_path,
            restricted=True,
            generated_by="admin1",
        )
        html = report_mod.render_html(restricted)
    assert "hunter2" not in json.dumps(standard)
    assert standard["report"]["evidence"][0]["value"] is None
    assert restricted["report"]["evidence"][0]["value"] == "hunter2"
    assert restricted["report"]["mode"].startswith("RESTRICTED")
    assert "RESTRICTED" in html
    assert "hunter2" in html


# --------------------------------------------------------------------- API


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
        analysis_store.record_batch(conn, CAPTURE_ID, [_http_packet()])
        analysis_store.record_batch(conn, CAPTURE_ID, [_response_packet()])
        evidence_store.seal_candidates(
            conn,
            CAPTURE_ID,
            [
                {
                    "type": "PASSWORD",
                    "field": "form: password",
                    "value": "hunter2",
                    "source": "http.form",
                    "src": "10.0.0.5",
                    "dst": "10.0.0.9",
                    "host": "portal.example",
                    "protocol": "http",
                    "transport_security": "plaintext",
                    "ts": 1700000000.0,
                    "meta": {},
                }
            ],
            profile="C",
            data_dir=tmp_path,
        )
        rules_mod.run_and_store(conn, CAPTURE_ID, data_dir=None)
    with TestClient(app) as test_client:
        yield test_client


def _login(client: TestClient, username: str, password: str) -> dict:
    response = client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_web_endpoints_permissions(client: TestClient) -> None:
    _login(client, "testauditor", "auditor-pw-123")
    assert client.get(f"/api/captures/{CAPTURE_ID}/web/apps").status_code == 200
    assert client.get(f"/api/captures/{CAPTURE_ID}/web/cookies").status_code == 200
    assert client.get(f"/api/captures/{CAPTURE_ID}/web/headers").status_code == 200
    assert client.get(f"/api/captures/{CAPTURE_ID}/web/tokens").status_code == 403
    assert client.get(f"/api/captures/{CAPTURE_ID}/web/flows").status_code == 403

    _login(client, "testanalyst", "analyst-pw-123")
    tokens = client.get(f"/api/captures/{CAPTURE_ID}/web/tokens")
    assert tokens.status_code == 200
    assert "hunter2" not in tokens.text
    apps = client.get(f"/api/captures/{CAPTURE_ID}/web/apps").json()
    assert apps["applications"][0]["host"] == "portal.example"


def test_case_api_roles_and_csrf(client: TestClient) -> None:
    auditor = _login(client, "testauditor", "auditor-pw-123")
    assert client.get("/api/cases").status_code == 200
    denied = client.post(
        "/api/cases",
        json={"title": "auditor case", "summary": ""},
        headers={"X-CSRF-Token": auditor["csrf_token"]},
    )
    assert denied.status_code == 403

    analyst = _login(client, "testanalyst", "analyst-pw-123")
    no_csrf = client.post("/api/cases", json={"title": "credential leak", "summary": ""})
    assert no_csrf.status_code == 403
    created = client.post(
        "/api/cases",
        json={"title": "credential leak", "summary": "portal"},
        headers={"X-CSRF-Token": analyst["csrf_token"]},
    )
    assert created.status_code == 200, created.text
    case_id = created.json()["id"]
    added = client.post(
        f"/api/cases/{case_id}/items",
        json={
            "item_type": "evidence",
            "item_id": "EVD-000001",
            "capture_id": CAPTURE_ID,
            "note": "leaked password",
        },
        headers={"X-CSRF-Token": analyst["csrf_token"]},
    )
    assert added.status_code == 200
    detail = client.get(f"/api/cases/{case_id}").json()
    assert detail["items"][0]["item_type"] == "evidence"


def test_report_api_permissions_and_audit(client: TestClient) -> None:
    analyst = _login(client, "testanalyst", "analyst-pw-123")
    standard = client.get(f"/api/captures/{CAPTURE_ID}/report?format=json")
    assert standard.status_code == 200
    assert "hunter2" not in standard.text
    assert standard.headers["content-disposition"].startswith("attachment")

    restricted = client.get(
        f"/api/captures/{CAPTURE_ID}/report?format=json&restricted=true"
    )
    assert restricted.status_code == 403
    assert "EXPORT_SENSITIVE_EVIDENCE" in restricted.json()["detail"]

    _login(client, "testadmin", "admin-pw-123")
    allowed = client.get(
        f"/api/captures/{CAPTURE_ID}/report?format=html&restricted=true"
    )
    assert allowed.status_code == 200
    assert "hunter2" in allowed.text
    with client.app.state.db.connect() as conn:
        actions = [event["action"] for event in list_events(conn, 50)]
    assert "REPORT_EXPORTED" in actions
    assert analyst  # session fixture still valid


def test_timeline_and_graph_endpoints(client: TestClient) -> None:
    _login(client, "testanalyst", "analyst-pw-123")
    timeline = client.get(f"/api/captures/{CAPTURE_ID}/timeline")
    assert timeline.status_code == 200
    assert timeline.json()["events"]
    assert "hunter2" not in timeline.text
    graph = client.get(f"/api/captures/{CAPTURE_ID}/graph?mode=connection")
    assert graph.status_code == 200
    assert graph.json()["nodes"]
