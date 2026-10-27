import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netherglass import __main__ as cli
from netherglass.api.app import create_app
from netherglass.config import AppConfig
from netherglass.emergency import EmergencyStop
from netherglass.security.audit import list_events
from netherglass.security.auth import create_user
from netherglass.store.db import Database

from fake_source import FakeSource
from pcap_gen import sample_capture


@pytest.fixture()
def client(tmp_path: Path):
    config = AppConfig(data_dir=tmp_path)
    app = create_app(config)
    app.state.capture._select_source_class = lambda: FakeSource  # type: ignore
    with app.state.db.connect() as conn:
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


def _import_sample(client: TestClient) -> str:
    session = _login(client, "testanalyst", "analyst-pw-123")
    pcap = sample_capture(Path(client.app.state.config.data_dir) / "sample.pcap")
    response = client.post(
        "/api/capture/import",
        json={"path": str(pcap)},
        headers={"X-CSRF-Token": session["csrf_token"]},
    )
    assert response.status_code == 200, response.text
    return response.json()["capture_id"]


def test_export_pcapng_converts_and_audits(client: TestClient) -> None:
    if shutil.which("mergecap") is None:
        pytest.skip("mergecap not installed")
    capture_id = _import_sample(client)
    response = client.get(f"/api/captures/{capture_id}/export?format=pcapng")
    assert response.status_code == 200, response.text
    assert "attachment" in response.headers["content-disposition"]
    assert response.content[:4] == b"\x0a\x0d\x0d\x0a"
    with client.app.state.db.connect() as conn:
        events = list_events(conn)
    exported = [e for e in events if e["action"] == "EVIDENCE_EXPORTED"]
    assert exported
    assert exported[0]["target"] == capture_id


def test_export_pcap_serves_source_when_format_matches(client: TestClient) -> None:
    capture_id = _import_sample(client)
    response = client.get(f"/api/captures/{capture_id}/export?format=pcap")
    assert response.status_code == 200, response.text
    assert response.content[:4] == b"\xd4\xc3\xb2\xa1"


def test_export_forbidden_for_auditor(client: TestClient) -> None:
    capture_id = _import_sample(client)
    _login(client, "testauditor", "auditor-pw-123")
    response = client.get(f"/api/captures/{capture_id}/export")
    assert response.status_code == 403
    assert "EXPORT_EVIDENCE" in response.json()["detail"]


def test_export_blocked_during_emergency(client: TestClient) -> None:
    capture_id = _import_sample(client)
    session = _login(client, "testanalyst", "analyst-pw-123")
    client.post(
        "/api/system/emergency-stop",
        json={"confirm": "EMERGENCY STOP"},
        headers={"X-CSRF-Token": session["csrf_token"]},
    )
    response = client.get(f"/api/captures/{capture_id}/export")
    assert response.status_code == 423


def test_export_running_capture_is_409(client: TestClient) -> None:
    session = _login(client, "testanalyst", "analyst-pw-123")
    headers = {"X-CSRF-Token": session["csrf_token"]}
    start = client.post("/api/capture/start", json={"interface": "lo"}, headers=headers)
    assert start.status_code == 200, start.text
    capture_id = start.json()["capture_id"]
    response = client.get(f"/api/captures/{capture_id}/export")
    assert response.status_code == 409
    client.post("/api/capture/stop", json={}, headers=headers)


def _state_db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "netherglass.db")
    db.migrate()
    return db


def test_cli_panic_sets_stop_state_and_audits(tmp_path: Path, capsys) -> None:
    code = cli.main(
        ["panic", "--reason", "suspected compromise", "--data-dir", str(tmp_path)]
    )
    assert code == 0
    assert "active" in capsys.readouterr().out
    db = _state_db(tmp_path)
    assert EmergencyStop(db).is_stopped() is True
    with db.connect() as conn:
        events = list_events(conn)
    assert events[0]["action"] == "EMERGENCY_SECURITY_STOP"
    assert events[0]["actor"].startswith("cli:")
    assert "suspected compromise" in json.dumps(events[0]["details"])


def test_cli_panic_is_idempotent_and_redacts(tmp_path: Path) -> None:
    secret = "token=abcdefghijklmnop0123456789"
    assert cli.main(["panic", "--reason", secret, "--data-dir", str(tmp_path)]) == 0
    assert cli.main(["panic", "--reason", "second", "--data-dir", str(tmp_path)]) == 0
    db = _state_db(tmp_path)
    with db.connect() as conn:
        events = list_events(conn)
    actions = [e["action"] for e in events]
    assert actions.count("EMERGENCY_SECURITY_STOP") == 1
    assert "abcdefghijklmnop0123456789" not in json.dumps(events[0]["details"])
