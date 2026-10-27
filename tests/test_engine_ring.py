import threading
import time
from pathlib import Path

import pytest

from netherglass.capture.engine import ActiveCapture, CaptureEngine
from netherglass.config import AppConfig
from netherglass.emergency import EmergencyStop
from netherglass.store import packets as packets_store
from netherglass.store.db import Database

from fake_source import FakeSource


@pytest.fixture()
def engine(tmp_path: Path):
    config = AppConfig(data_dir=tmp_path)
    db = Database(config.db_path())
    db.migrate()
    emergency = EmergencyStop(db)
    capture_engine = CaptureEngine(config, db, emergency, poll_seconds=0.05)
    capture_engine._select_source_class = lambda: FakeSource  # type: ignore[method-assign]
    yield capture_engine, db


def test_decoder_never_decodes_open_ring_file(engine, tmp_path: Path, monkeypatch) -> None:
    capture_engine, _ = engine
    capture_dir = tmp_path / "cap"
    capture_dir.mkdir()
    active = ActiveCapture("cap-test", FakeSource("lo", capture_dir), capture_dir)
    calls: list[str] = []

    def fake_iter(path, tshark=None, patterns=None):
        calls.append(Path(path).name)
        return iter(())

    monkeypatch.setattr(
        "netherglass.capture.engine.decode_mod.iter_ek_packets", fake_iter
    )

    (capture_dir / "cap_00001.pcapng").write_bytes(b"still-open")
    capture_engine._decode_closed_files(active, only_closed=True)
    assert calls == []

    (capture_dir / "cap_00002.pcapng").write_bytes(b"still-open")
    capture_engine._decode_closed_files(active, only_closed=True)
    assert calls == ["cap_00001.pcapng"]
    capture_engine._decode_closed_files(active, only_closed=True)
    assert calls == ["cap_00001.pcapng"]

    capture_engine._decode_closed_files(active, only_closed=False)
    assert calls == ["cap_00001.pcapng", "cap_00002.pcapng"]


def test_writer_waits_for_sentinel_after_stop(engine, tmp_path: Path) -> None:
    capture_engine, db = engine
    capture_dir = tmp_path / "cap"
    capture_dir.mkdir()
    active = ActiveCapture("cap-writer", FakeSource("lo", capture_dir), capture_dir)
    with db.connect() as conn:
        packets_store.create_capture(
            conn,
            capture_id=active.id,
            created_at="2026-01-01T00:00:00Z",
            interface="lo",
            profile="B",
            source="fake",
            bpf=None,
        )
    active.stop_flag.set()
    writer = threading.Thread(target=capture_engine._writer_loop, args=(active,), daemon=True)
    writer.start()
    for index in range(3):
        active.queue.put(
            {
                "num": index + 1,
                "ts": 1700000000.0 + index,
                "src": "10.0.0.1",
                "dst": "10.0.0.2",
                "sport": 1000,
                "dport": 443,
                "proto": "tcp",
                "length": 60,
                "info": None,
                "raw": None,
            }
        )
    time.sleep(0.4)
    assert writer.is_alive()
    active.queue.put(None)
    writer.join(timeout=5)
    assert not writer.is_alive()
    with db.connect() as conn:
        count = conn.execute(
            "SELECT COUNT(*) AS n FROM packets WHERE capture_id = ?", (active.id,)
        ).fetchone()["n"]
    assert count == 3
