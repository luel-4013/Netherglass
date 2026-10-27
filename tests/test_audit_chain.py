from pathlib import Path

from netherglass.security.audit import append_event, list_events, verify_chain
from netherglass.store.db import Database


def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "audit.db")
    db.migrate()
    return db


def test_chain_valid_after_appends(tmp_path: Path) -> None:
    db = _db(tmp_path)
    with db.connect() as conn:
        append_event(conn, actor="a", action="ONE")
        append_event(conn, actor="a", action="TWO", details={"k": "v"})
        append_event(conn, actor="b", action="THREE")
        valid, count = verify_chain(conn)
    assert valid is True
    assert count == 3


def test_tamper_detected(tmp_path: Path) -> None:
    db = _db(tmp_path)
    with db.connect() as conn:
        append_event(conn, actor="a", action="ONE")
        append_event(conn, actor="a", action="TWO")
        conn.execute("UPDATE audit_log SET action = 'HACKED' WHERE id = 2")
        valid, index = verify_chain(conn)
    assert valid is False
    assert index == 2


def test_events_are_scrubbed(tmp_path: Path) -> None:
    db = _db(tmp_path)
    with db.connect() as conn:
        append_event(conn, actor="a", action="NOTE", details={"note": "password=hunter2"})
        events = list_events(conn)
    assert "hunter2" not in str(events[0]["details"])
