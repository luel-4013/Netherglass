"""Incremental PcapNG packet counting for honest live capture counters.

dumpcap only reports totals when it exits, so the dashboard would otherwise
show `captured: 0` during a running capture. This scanner walks PcapNG block
headers incrementally (only newly appended bytes are parsed each poll) and
counts Enhanced/Simple/obsolete Packet Blocks. Ring files removed by rotation
retire their counts so the session total stays cumulative.
"""

from __future__ import annotations

import struct
import threading
from pathlib import Path

SHB = 0x0A0D0D0A
PB = 0x00000002
SPB = 0x00000003
EPB = 0x00000006
MAX_BLOCK = 64 * 1024 * 1024


def _scan(path: Path, offset: int, size: int) -> tuple[int, int]:
    endian = "<"
    count = 0
    with path.open("rb") as handle:
        if offset == 0:
            handle.seek(0)
            head = handle.read(12)
            if len(head) < 12:
                return 0, 0
            block_type, block_len = struct.unpack("<II", head[:8])
            if block_type != SHB or not (12 <= block_len <= MAX_BLOCK):
                return 0, 0
            bom = head[8:12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                return 0, 0
        handle.seek(offset)
        while offset + 12 <= size:
            header = handle.read(8)
            if len(header) < 8:
                break
            block_type, block_len = struct.unpack(endian + "II", header)
            if not (12 <= block_len <= MAX_BLOCK) or offset + block_len > size:
                break
            if block_type == SHB:
                handle.seek(offset + 8)
                bom = handle.read(4)
                if bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                handle.seek(offset + 8)
            elif block_type in (EPB, SPB, PB):
                count += 1
            offset += block_len
            handle.seek(offset)
    return count, offset


class PcapngCounter:
    def __init__(self) -> None:
        self._offsets: dict[str, int] = {}
        self._counts: dict[str, int] = {}
        self._identities: dict[str, tuple[int, int]] = {}
        self._retired = 0
        self._lock = threading.Lock()

    def update(self, paths: list[Path]) -> int:
        with self._lock:
            return self._update_locked(paths)

    def _update_locked(self, paths: list[Path]) -> int:
        seen: set[str] = set()
        for path in paths:
            key = str(path)
            seen.add(key)
            try:
                info = path.stat()
                size = info.st_size
            except OSError:
                continue
            identity = (info.st_dev, info.st_ino)
            if self._identities.get(key) not in (None, identity):
                self._retired += self._counts.pop(key, 0)
                self._offsets.pop(key, None)
            self._identities[key] = identity
            offset = self._offsets.get(key, 0)
            if size < offset:
                self._retired += self._counts.pop(key, 0)
                offset = 0
            if size <= offset:
                self._offsets[key] = offset
                self._counts.setdefault(key, 0)
                continue
            added, new_offset = _scan(path, offset, size)
            self._counts[key] = self._counts.get(key, 0) + added
            self._offsets[key] = new_offset
        for key in [k for k in self._offsets if k not in seen]:
            self._retired += self._counts.pop(key, 0)
            self._offsets.pop(key, None)
            self._identities.pop(key, None)
        return self.total()

    def total(self) -> int:
        return self._retired + sum(self._counts.values())
