import json
from pathlib import Path

import pytest

from netherglass.emergency import EmergencyStop
from netherglass.security.audit import list_events, verify_chain
from netherglass.store.db import Database


@pytest.fixture()
def estop(tmp_path: Path) -> EmergencyStop:
    db = Database(tmp_path / "ng.db")
    db.migrate()
    return EmergencyStop(db)


def test_initial_state_allows_capture(estop: EmergencyStop) -> None:
    assert estop.is_stopped() is False
    assert estop.capture_allowed() is True


def test_trigger_stops_and_audits(estop: EmergencyStop) -> None:
    status = estop.trigger(actor="analyst01", reason="suspected compromise")
    assert status["emergency_stopped"] is True
    assert status["capture"] == "STOPPED"
    assert status["sensitive_evidence"] == "LOCKED"
    assert estop.capture_allowed() is False
    assert estop.capture_halt.is_set()
    with estop.db.connect() as conn:
        events = list_events(conn)
        valid, _ = verify_chain(conn)
    assert events[0]["action"] == "EMERGENCY_SECURITY_STOP"
    assert valid is True


def test_recover_requires_reason(estop: EmergencyStop) -> None:
    estop.trigger(actor="analyst01")
    with pytest.raises(ValueError):
        estop.recover(actor="admin", reason="   ")


def test_recover_clears_state(estop: EmergencyStop) -> None:
    estop.trigger(actor="analyst01")
    status = estop.recover(actor="admin", reason="false alarm cleared")
    assert status["emergency_stopped"] is False
    assert estop.capture_allowed() is True
    assert not estop.capture_halt.is_set()
    with estop.db.connect() as conn:
        actions = [e["action"] for e in list_events(conn)]
    assert actions[0] == "EMERGENCY_RECOVERY"
    assert actions[1] == "EMERGENCY_SECURITY_STOP"


def test_no_secrets_in_audit_details(estop: EmergencyStop) -> None:
    estop.trigger(
        actor="analyst01",
        reason="token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk",
    )
    with estop.db.connect() as conn:
        events = list_events(conn)
    detail_text = json.dumps(events[0]["details"])
    assert "eyJhbGciOiJIUzI1NiJ9" not in detail_text
