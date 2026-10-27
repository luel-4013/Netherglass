from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netherglass.api.app import create_app
from netherglass.config import AppConfig
from netherglass.security.auth import create_user


@pytest.fixture()
def client(tmp_path: Path):
    config = AppConfig(data_dir=tmp_path)
    app = create_app(config)
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


def test_health_is_public(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_interfaces_requires_auth(client: TestClient) -> None:
    assert client.get("/api/system/interfaces").status_code == 401


def test_login_and_fetch_interfaces(client: TestClient) -> None:
    _login(client, "testanalyst", "analyst-pw-123")
    response = client.get("/api/system/interfaces")
    assert response.status_code == 200
    names = {i["name"] for i in response.json()["interfaces"]}
    assert "lo" in names


def test_readiness_and_config_endpoints(client: TestClient) -> None:
    _login(client, "testanalyst", "analyst-pw-123")
    readiness = client.get("/api/system/readiness")
    assert readiness.status_code == 200
    assert any(s["id"] == "offline" for s in readiness.json()["sources"])
    config = client.get("/api/system/config")
    assert config.status_code == 200
    body = config.json()
    assert {p["id"] for p in body["profiles"]} == {"A", "B", "C"}
    assert body["profile"] == "B"


def test_wrong_password_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/auth/login", json={"username": "testadmin", "password": "nope"}
    )
    assert response.status_code == 401


def test_login_rate_limit(client: TestClient) -> None:
    for _ in range(5):
        client.post(
            "/api/auth/login", json={"username": "testadmin", "password": "bad"}
        )
    response = client.post(
        "/api/auth/login", json={"username": "testadmin", "password": "admin-pw-123"}
    )
    assert response.status_code == 429


def test_emergency_stop_flow(client: TestClient) -> None:
    session = _login(client, "testanalyst", "analyst-pw-123")
    response = client.post(
        "/api/system/emergency-stop",
        json={"confirm": "EMERGENCY STOP", "reason": "test"},
        headers={"X-CSRF-Token": session["csrf_token"]},
    )
    assert response.status_code == 200
    assert response.json()["emergency_stopped"] is True
    assert client.get("/api/health").json()["emergency_stopped"] is True


def test_emergency_stop_requires_confirmation_phrase(client: TestClient) -> None:
    session = _login(client, "testanalyst", "analyst-pw-123")
    response = client.post(
        "/api/system/emergency-stop",
        json={"confirm": "yes"},
        headers={"X-CSRF-Token": session["csrf_token"]},
    )
    assert response.status_code == 400


def test_emergency_stop_requires_csrf(client: TestClient) -> None:
    _login(client, "testanalyst", "analyst-pw-123")
    response = client.post(
        "/api/system/emergency-stop", json={"confirm": "EMERGENCY STOP"}
    )
    assert response.status_code == 403


def test_recovery_permission_separation(client: TestClient) -> None:
    session = _login(client, "testanalyst", "analyst-pw-123")
    client.post(
        "/api/system/emergency-stop",
        json={"confirm": "EMERGENCY STOP"},
        headers={"X-CSRF-Token": session["csrf_token"]},
    )
    response = client.post(
        "/api/system/emergency-recover",
        json={"reason": "resolved"},
        headers={"X-CSRF-Token": session["csrf_token"]},
    )
    assert response.status_code == 403


def test_admin_can_recover(client: TestClient) -> None:
    session = _login(client, "testanalyst", "analyst-pw-123")
    client.post(
        "/api/system/emergency-stop",
        json={"confirm": "EMERGENCY STOP"},
        headers={"X-CSRF-Token": session["csrf_token"]},
    )
    admin = _login(client, "testadmin", "admin-pw-123")
    response = client.post(
        "/api/system/emergency-recover",
        json={"reason": "false alarm"},
        headers={"X-CSRF-Token": admin["csrf_token"]},
    )
    assert response.status_code == 200
    assert response.json()["emergency_stopped"] is False


def test_recovery_requires_reason(client: TestClient) -> None:
    admin = _login(client, "testadmin", "admin-pw-123")
    response = client.post(
        "/api/system/emergency-recover",
        json={"reason": ""},
        headers={"X-CSRF-Token": admin["csrf_token"]},
    )
    assert response.status_code == 400


def test_audit_permission(client: TestClient) -> None:
    _login(client, "testanalyst", "analyst-pw-123")
    assert client.get("/api/audit").status_code == 403
    _login(client, "testadmin", "admin-pw-123")
    response = client.get("/api/audit")
    assert response.status_code == 200
    body = response.json()
    assert body["chain_valid"] is True
    assert any(e["action"] == "LOGIN_SUCCESS" for e in body["events"])


def test_auditor_sees_audit_but_cannot_stop_recovery(client: TestClient) -> None:
    session = _login(client, "testauditor", "auditor-pw-123")
    assert client.get("/api/audit").status_code == 200
    response = client.post(
        "/api/system/emergency-recover",
        json={"reason": "nope"},
        headers={"X-CSRF-Token": session["csrf_token"]},
    )
    assert response.status_code == 403


def test_session_endpoint_unauthenticated(client: TestClient) -> None:
    response = client.get("/api/auth/session")
    assert response.status_code == 200
    assert response.json()["authenticated"] is False


def test_logout_revokes_session(client: TestClient) -> None:
    session = _login(client, "testauditor", "auditor-pw-123")
    response = client.post(
        "/api/auth/logout", headers={"X-CSRF-Token": session["csrf_token"]}
    )
    assert response.status_code == 200
    assert client.get("/api/system/interfaces").status_code == 401
