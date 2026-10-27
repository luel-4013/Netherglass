import hashlib
import json
import shutil
import time
from pathlib import Path

import pytest

import netherglass.capture.decode as decode_mod
from netherglass.capture.engine import CaptureEngine, CaptureError
from netherglass.config import AppConfig
from netherglass.emergency import EmergencyStop
from netherglass.store import packets as packets_store
from netherglass.store.db import Database

from pcap_gen import sample_capture

HAS_TSHARK = shutil.which("tshark") is not None


@pytest.fixture()
def env(tmp_path: Path):
    config = AppConfig(data_dir=tmp_path)
    db = Database(config.db_path())
    db.migrate()
    emergency = EmergencyStop(db)
    engine = CaptureEngine(config, db, emergency, poll_seconds=0.05)
    yield config, db, emergency, engine


def _fake_packets(count: int = 3):
    def generator(path, tshark=None, patterns=None):
        for i in range(count):
            yield {
                "num": i + 1,
                "ts": 1700000000.0 + i,
                "src": "10.0.0.5" if i == 0 else "192.168.1.10",
                "dst": "10.0.0.53" if i == 0 else "93.184.216.34",
                "sport": 53210 + i,
                "dport": 53 if i == 0 else 443,
                "proto": "dns" if i == 0 else "tcp",
                "length": 78 + i,
                "info": f"fake packet {i + 1}",
            }

    return generator


def _wait_ready(db: Database, capture_id: str, timeout: float = 10.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with db.connect() as conn:
            row = packets_store.get_capture(conn, capture_id)
        if row and row["status"] != "decoding":
            return row
        time.sleep(0.05)
    raise AssertionError("import did not complete in time")


def test_import_records_hash_and_decodes(env, tmp_path: Path, monkeypatch) -> None:
    config, db, _, engine = env
    monkeypatch.setattr(decode_mod, "iter_ek_packets", _fake_packets(3))
    source = tmp_path / "outside-sample.pcap"
    source.write_bytes(b"not-a-real-pcap-but-content-matters")
    expected_hash = hashlib.sha256(source.read_bytes()).hexdigest()

    result = engine.import_file(source, actor="tester")
    assert result["sha256"] == expected_hash
    row = _wait_ready(db, result["capture_id"])
    assert row["status"] == "ready"
    assert row["packets_captured"] == 3

    capture_dir = config.data_dir / "captures" / result["capture_id"]
    manifest = json.loads((capture_dir / "manifest.json").read_text())
    assert manifest["sha256"] == expected_hash
    assert manifest["decoded_packets"] == 3
    stored = capture_dir / "source" / "outside-sample.pcap"
    assert stored.exists()
    assert hashlib.sha256(stored.read_bytes()).hexdigest() == expected_hash

    with db.connect() as conn:
        page = packets_store.list_packets(conn, result["capture_id"])
        flows = packets_store.list_flows(conn, result["capture_id"])
    assert page["total"] == 3
    assert len(flows) == 2
    dns_flow = [f for f in flows if f["proto"] == "dns"][0]
    assert dns_flow["dport"] == 53
    assert dns_flow["packets"] == 1


def test_import_missing_file_rejected(env, tmp_path: Path) -> None:
    _, _, _, engine = env
    with pytest.raises(CaptureError) as exc:
        engine.import_file(tmp_path / "nope.pcap", actor="tester")
    assert exc.value.code == 404


def test_import_blocked_during_emergency(env, tmp_path: Path) -> None:
    _, _, emergency, engine = env
    source = tmp_path / "x.pcap"
    source.write_bytes(b"data")
    emergency.trigger(actor="tester")
    with pytest.raises(CaptureError) as exc:
        engine.import_file(source, actor="tester")
    assert exc.value.code == 423


def test_import_audit_events(env, tmp_path: Path, monkeypatch) -> None:
    _, db, _, engine = env
    monkeypatch.setattr(decode_mod, "iter_ek_packets", _fake_packets(1))
    source = tmp_path / "audit-me.pcap"
    source.write_bytes(b"x")
    result = engine.import_file(source, actor="tester")
    _wait_ready(db, result["capture_id"])
    with db.connect() as conn:
        actions = [
            row["action"]
            for row in conn.execute(
                "SELECT action FROM audit_log WHERE target = ? ORDER BY id",
                (result["capture_id"],),
            )
        ]
    assert actions == [
        "PCAP_IMPORT_STARTED",
        "PCAP_IMPORT_COMPLETED",
        "ANALYSIS_COMPLETED",
    ]


@pytest.mark.skipif(not HAS_TSHARK, reason="tshark not installed")
def test_import_real_tshark_end_to_end(env, tmp_path: Path) -> None:
    _, db, _, engine = env
    source = sample_capture(tmp_path / "real-sample.pcap")
    result = engine.import_file(source, actor="tester")
    row = _wait_ready(db, result["capture_id"])
    assert row["status"] == "ready", row["error"]
    assert row["packets_captured"] == 3
    with db.connect() as conn:
        page = packets_store.list_packets(conn, result["capture_id"])
        flows = packets_store.list_flows(conn, result["capture_id"])
    assert page["total"] == 3
    protos = {p["proto"] for p in page["packets"]}
    assert {"dns", "tcp", "icmp"} <= protos
    assert any("example.com" in (p["info"] or "") for p in page["packets"])
    assert len(flows) == 3
