import time
from pathlib import Path

import pytest

from netherglass.capture.engine import CaptureEngine, CaptureError
from netherglass.capture.sources import DumpcapSource, TcpdumpSource
from netherglass.config import AppConfig
from netherglass.emergency import EmergencyStop
from netherglass.store.db import Database

from fake_source import FakeSource


@pytest.fixture()
def env(tmp_path: Path):
    config = AppConfig(data_dir=tmp_path)
    db = Database(config.db_path())
    db.migrate()
    emergency = EmergencyStop(db)
    engine = CaptureEngine(config, db, emergency, poll_seconds=0.05)
    engine._select_source_class = lambda: FakeSource  # type: ignore[method-assign]
    yield config, db, emergency, engine


def _wait_until(predicate, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def test_start_and_stop_lifecycle(env) -> None:
    config, db, emergency, engine = env
    started = engine.start_live("lo", actor="tester")
    assert started["active"] is True
    assert started["interface"] == "lo"
    assert started["source"] == "fake"
    status = engine.status()
    assert status["packets_captured"] == 42
    assert status["packets_decoded"] == 0
    summary = engine.stop(actor="tester", reason="done")
    assert summary["status"] == "stopped"
    assert summary["packets_captured"] == 42
    assert engine.status()["active"] is False
    assert (config.data_dir / "captures" / summary["capture_id"] / "manifest.json").exists()
    with db.connect() as conn:
        row = conn.execute(
            "SELECT status, packets_captured FROM captures WHERE id = ?",
            (summary["capture_id"],),
        ).fetchone()
    assert row["status"] == "stopped"
    assert row["packets_captured"] == 42


def test_double_start_rejected(env) -> None:
    _, _, _, engine = env
    engine.start_live("lo", actor="tester")
    with pytest.raises(CaptureError) as exc:
        engine.start_live("lo", actor="tester")
    assert exc.value.code == 409
    engine.stop(actor="tester")


def test_stop_without_capture_rejected(env) -> None:
    _, _, _, engine = env
    with pytest.raises(CaptureError):
        engine.stop(actor="tester")


def test_unknown_interface_rejected(env) -> None:
    _, _, _, engine = env
    with pytest.raises(CaptureError) as exc:
        engine.start_live("definitely-not-real0", actor="tester")
    assert exc.value.code == 400


def test_profile_a_refuses_live_capture(env) -> None:
    config, _, _, engine = env
    config.profile = "A"
    with pytest.raises(CaptureError) as exc:
        engine.start_live("lo", actor="tester")
    assert exc.value.code == 400
    assert "metadata only" in str(exc.value)


def test_scope_exclusion_refuses_capture(env) -> None:
    config, _, _, engine = env
    config.scope.excluded_interfaces = ["lo"]
    with pytest.raises(CaptureError) as exc:
        engine.start_live("lo", actor="tester")
    assert exc.value.code == 400


def test_no_source_available(env, monkeypatch) -> None:
    _, _, _, engine = env
    engine._select_source_class = CaptureEngine._select_source_class.__get__(engine)
    monkeypatch.setattr(DumpcapSource, "available", staticmethod(lambda: False))
    monkeypatch.setattr(TcpdumpSource, "available", staticmethod(lambda: False))
    with pytest.raises(CaptureError) as exc:
        engine.start_live("lo", actor="tester")
    assert exc.value.code == 409
    message = str(exc.value).lower()
    assert "no live capture source" in message or "not executable" in message


def test_emergency_halt_stops_capture(env) -> None:
    _, db, emergency, engine = env
    engine.start_live("lo", actor="tester")
    assert engine.status()["active"] is True
    emergency.trigger(actor="tester", reason="test halt")
    assert _wait_until(lambda: not engine.status()["active"]), "capture did not halt"
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT action, details FROM audit_log WHERE action = 'CAPTURE_STOPPED'"
        ).fetchall()
    assert rows
    assert "emergency security stop" in rows[-1]["details"]


def test_capture_refused_during_emergency(env) -> None:
    _, _, emergency, engine = env
    emergency.trigger(actor="tester")
    with pytest.raises(CaptureError) as exc:
        engine.start_live("lo", actor="tester")
    assert exc.value.code == 423


def test_start_records_audit_event(env) -> None:
    _, db, _, engine = env
    engine.start_live("lo", actor="tester", bpf="tcp port 443")
    with db.connect() as conn:
        row = conn.execute(
            "SELECT details FROM audit_log WHERE action = 'CAPTURE_STARTED'"
        ).fetchone()
    assert row is not None
    assert "tcp port 443" in row["details"]
    engine.stop(actor="tester")
