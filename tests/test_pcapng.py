import shutil
import subprocess
from pathlib import Path

import pytest

from netherglass.capture.pcapng import PcapngCounter

from pcap_gen import sample_capture

TSHARK = shutil.which("tshark")

pytestmark = pytest.mark.skipif(TSHARK is None, reason="tshark not installed")


def _pcapng(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    pcap = sample_capture(tmp_path / "sample.pcap")
    target = tmp_path / "sample.pcapng"
    subprocess.run(
        [TSHARK, "-r", str(pcap), "-w", str(target)],
        check=True,
        capture_output=True,
    )
    return target


def test_counter_counts_all_packet_blocks(tmp_path: Path) -> None:
    path = _pcapng(tmp_path)
    counter = PcapngCounter()
    assert counter.update([path]) == 3
    assert counter.update([path]) == 3


def test_counter_handles_partial_tail_incrementally(tmp_path: Path) -> None:
    path = _pcapng(tmp_path)
    data = path.read_bytes()
    path.write_bytes(data[:-5])
    counter = PcapngCounter()
    partial = counter.update([path])
    assert 0 <= partial <= 3
    with path.open("ab") as handle:
        handle.write(data[-5:])
    assert counter.update([path]) == 3


def test_counter_retires_rotated_files(tmp_path: Path) -> None:
    first = _pcapng(tmp_path / "one")
    second = _pcapng(tmp_path / "two")
    counter = PcapngCounter()
    assert counter.update([first, second]) == 6
    first.unlink()
    assert counter.update([second]) == 6
    assert counter.update([second]) == 6


def test_counter_treats_reused_ring_name_as_new_file(tmp_path: Path) -> None:
    path = _pcapng(tmp_path)
    counter = PcapngCounter()
    assert counter.update([path]) == 3
    path.unlink()
    counter.update([])
    _pcapng(tmp_path)
    assert counter.update([path]) == 6
