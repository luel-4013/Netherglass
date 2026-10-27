"""Shared fake capture source for engine/API tests (no privileges needed)."""

from __future__ import annotations

from pathlib import Path


class FakeSource:
    name = "fake"

    def __init__(
        self,
        interface: str,
        out_dir: Path,
        *,
        bpf: str | None = None,
        chunk_seconds: int = 5,
    ) -> None:
        self.interface = interface
        self.out_dir = Path(out_dir)
        self.bpf = bpf
        self.chunk_seconds = chunk_seconds
        self.started = False
        self.stopped = False
        self._returncode: int | None = None

    @staticmethod
    def available() -> bool:
        return True

    def start(self) -> None:
        self.started = True

    def stop(self, timeout: float = 3.0) -> None:
        self.stopped = True
        self._returncode = 0

    def alive(self) -> bool:
        return self.started and not self.stopped

    def returncode(self) -> int | None:
        return self._returncode

    def counters(self) -> dict:
        return {
            "packets_captured": 42,
            "packets_dropped": 0,
            "last_error": None,
        }
