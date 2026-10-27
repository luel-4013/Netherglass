from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netherglass.api.app import create_app
from netherglass.config import AppConfig
from netherglass.security.auth import create_user
from netherglass.store import packets as packets_store

from fake_source import FakeSource


@pytest.fixture()
def client(tmp_path: Path, monkeypatch):
    config = AppConfig(data_dir=tmp_path)
    app = create_app(config)
    app.state.capture._select_source_class = lambda: FakeSource  # type: ignore
    with app.state.db.connect() as conn:
        create_user(conn, "testadmin", "admin-pw-123", "admin")
        create_user(conn, "testanalyst", "analyst-pw-123", "analyst")
        create_user(conn, "testauditor", "auditor-pw-123", "auditor")
    with TestClient(app) as test_client:
        yield test_client


def _login(client: TestClient, username: str, password: str) -> dict:
    response = client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_capture_requires_auth(client: TestClient) -> None:
    assert client.get("/api/capture/status").status_code == 401
    assert client.get("/api/packets?capture_id=x").status_code == 401
    assert client.get("/api/captures").status_code == 401


def test_live_capture_start_status_stop(client: TestClient) -> None:
    session = _login(client, "testanalyst", "analyst-pw-123")
    headers = {"X-CSRF-Token": session["csrf_token"]}
    start = client.post(
        "/api/capture/start", json={"interface": "lo"}, headers=headers
    )
    assert start.status_code == 200, start.text
    body = start.json()
    assert body["active"] is True
    capture_id = body["capture_id"]

    status = client.get("/api/capture/status").json()
    assert status["active"] is True
    assert status["packets_captured"] == 42
    assert "decode_drops" in status

    stop = client.post("/api/capture/stop", json={}, headers=headers)
    assert stop.status_code == 200
    assert stop.json()["status"] == "stopped"

    assert client.get("/api/capture/status").json()["active"] is False
    captures = client.get("/api/captures").json()["captures"]
    assert any(c["id"] == capture_id for c in captures)


def test_start_requires_csrf(client: TestClient) -> None:
    _login(client, "testanalyst", "analyst-pw-123")
    response = client.post("/api/capture/start", json={"interface": "lo"})
    assert response.status_code == 403


def test_auditor_cannot_control_capture(client: TestClient) -> None:
    session = _login(client, "testauditor", "auditor-pw-123")
    response = client.post(
        "/api/capture/start",
        json={"interface": "lo"},
        headers={"X-CSRF-Token": session["csrf_token"]},
    )
    assert response.status_code == 403
    assert "CONTROL_CAPTURE" in response.json()["detail"]


def test_profile_c_requires_full_capture_permission(client: TestClient) -> None:
    client.app.state.config.profile = "C"
    session = _login(client, "testanalyst", "analyst-pw-123")
    response = client.post(
        "/api/capture/start",
        json={"interface": "lo"},
        headers={"X-CSRF-Token": session["csrf_token"]},
    )
    assert response.status_code == 403
    assert "ENABLE_FULL_CAPTURE" in response.json()["detail"]


def test_capture_start_rejected_during_emergency(client: TestClient) -> None:
    session = _login(client, "testanalyst", "analyst-pw-123")
    headers = {"X-CSRF-Token": session["csrf_token"]}
    client.post(
        "/api/system/emergency-stop",
        json={"confirm": "EMERGENCY STOP"},
        headers=headers,
    )
    response = client.post(
        "/api/capture/start", json={"interface": "lo"}, headers=headers
    )
    assert response.status_code == 423


def test_unknown_interface_is_400(client: TestClient) -> None:
    session = _login(client, "testanalyst", "analyst-pw-123")
    response = client.post(
        "/api/capture/start",
        json={"interface": "eth-no-such0"},
        headers={"X-CSRF-Token": session["csrf_token"]},
    )
    assert response.status_code == 400


def test_packets_listing_and_filters(client: TestClient) -> None:
    session = _login(client, "testanalyst", "analyst-pw-123")
    db = client.app.state.db
    with db.connect() as conn:
        packets_store.create_capture(
            conn,
            capture_id="cap-test-1",
            created_at="2026-10-19T00:00:00+00:00",
            interface="lo",
            profile="B",
            source="import",
            bpf=None,
        )
        packets_store.insert_packets(
            conn,
            [
                {
                    "capture_id": "cap-test-1",
                    "num": 1,
                    "ts": 1.0,
                    "src": "10.0.0.5",
                    "dst": "10.0.0.53",
                    "sport": 53000,
                    "dport": 53,
                    "proto": "dns",
                    "length": 78,
                    "info": "DNS query example.com",
                },
                {
                    "capture_id": "cap-test-1",
                    "num": 2,
                    "ts": 2.0,
                    "src": "192.168.1.10",
                    "dst": "93.184.216.34",
                    "sport": 49152,
                    "dport": 443,
                    "proto": "tcp",
                    "length": 74,
                    "info": "TCP 49152 -> 443 [SYN]",
                },
            ],
        )
    _ = session

    page = client.get("/api/packets?capture_id=cap-test-1").json()
    assert page["total"] == 2
    assert page["packets"][0]["proto"] == "dns"

    dns_only = client.get("/api/packets?capture_id=cap-test-1&proto=dns").json()
    assert dns_only["total"] == 1

    by_addr = client.get("/api/packets?capture_id=cap-test-1&addr=93.184.216.34").json()
    assert by_addr["total"] == 1

    by_port = client.get("/api/packets?capture_id=cap-test-1&port=443").json()
    assert by_port["total"] == 1

    detail = client.get("/api/captures/cap-test-1").json()
    assert detail["decoded_packets"] == 2

    missing = client.get("/api/captures/does-not-exist")
    assert missing.status_code == 404


def test_capture_status_idle(client: TestClient) -> None:
    _login(client, "testauditor", "auditor-pw-123")
    status = client.get("/api/capture/status").json()
    assert status["active"] is False
