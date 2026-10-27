"""Live capture sources.

The preferred source is Wireshark's dumpcap: it drops privileges safely and
reports honest counters. tcpdump is the fallback. Every source:
- writes PcapNG ring files into the capture directory (bounded disk usage),
- reports captured/dropped counters parsed from the tool's own stderr,
- stops within seconds on request (SIGTERM, then SIGKILL),
- surfaces permission problems with exact remediation steps.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import threading
from pathlib import Path

WIRESHARK_GROUP_HELP = (
    "add your user to the wireshark group, then log out and back in: "
    "sudo usermod -aG wireshark $USER"
)

_DUMPCAP_CAPTURED_RE = re.compile(r"Packets captured:\s*(\d+)")
_DUMPCAP_DROPPED_RE = re.compile(
    r"Packets received/dropped on interface .*?:\s*(\d+)/(\d+)"
)
_TCPDUMP_CAPTURED_RE = re.compile(r"(\d+) packets captured")
_TCPDUMP_RECEIVED_RE = re.compile(r"(\d+) packets received by filter")
_TCPDUMP_DROPPED_RE = re.compile(r"(\d+) packets dropped by kernel")


class SourceError(RuntimeError):
    pass


def _default_ring(chunk_seconds: int) -> list[str]:
    return [f"duration:{chunk_seconds}", "files:10", "filesize:51200"]


class DumpcapSource:
    name = "dumpcap"

    def __init__(
        self,
        interface: str,
        out_dir: Path,
        *,
        bpf: str | None = None,
        chunk_seconds: int = 5,
        base_name: str = "cap",
    ) -> None:
        self.interface = interface
        self.out_dir = Path(out_dir)
        self.bpf = bpf
        self.chunk_seconds = chunk_seconds
        self.base_name = base_name
        self.proc: subprocess.Popen | None = None
        self.packets_captured = 0
        self.packets_dropped = 0
        self.last_error: str | None = None
        self._reader: threading.Thread | None = None
        self._stop_requested = False

    @staticmethod
    def available() -> bool:
        binary = shutil.which("dumpcap")
        return bool(binary) and os.access(binary, os.X_OK)

    def start(self) -> None:
        binary = shutil.which("dumpcap")
        if not binary:
            raise SourceError("dumpcap not installed - run: sudo pacman -S wireshark-cli")
        if not os.access(binary, os.X_OK):
            raise SourceError(
                f"dumpcap exists at {binary} but is not executable by this user; "
                + WIRESHARK_GROUP_HELP
            )
        self.out_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.out_dir, 0o700)
        target = self.out_dir / f"{self.base_name}.pcapng"
        cmd = [binary, "-i", self.interface, "-w", str(target)]
        for arg in _default_ring(self.chunk_seconds):
            cmd += ["-b", arg]
        if self.bpf:
            cmd += ["-f", self.bpf]
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        self._reader = threading.Thread(target=self._read_stderr, daemon=True)
        self._reader.start()
        self._verify_started()

    def _verify_started(self) -> None:
        assert self.proc is not None
        try:
            code = self.proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            return
        stderr = ""
        if self.proc.stderr:
            try:
                stderr = self.proc.stderr.read()
            except OSError:
                stderr = ""
        lowered = stderr.lower()
        if "permission denied" in lowered or "permission" in lowered:
            raise SourceError(f"dumpcap permission denied; {WIRESHARK_GROUP_HELP}")
        if "no such device" in lowered or "doesn't exist" in lowered:
            raise SourceError(f"interface '{self.interface}' not available to dumpcap")
        raise SourceError(
            f"dumpcap exited immediately (code {code}): {stderr.strip()[:300]}"
        )

    def _read_stderr(self) -> None:
        assert self.proc is not None and self.proc.stderr is not None
        for line in self.proc.stderr:
            match = _DUMPCAP_CAPTURED_RE.search(line)
            if match:
                self.packets_captured = max(self.packets_captured, int(match.group(1)))
                continue
            match = _DUMPCAP_DROPPED_RE.search(line)
            if match:
                self.packets_dropped = max(self.packets_dropped, int(match.group(2)))
                continue
            line = line.strip()
            if line:
                self.last_error = line

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def returncode(self) -> int | None:
        return self.proc.poll() if self.proc else None

    def stop(self, timeout: float = 3.0) -> None:
        if self._stop_requested:
            return
        self._stop_requested = True
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGINT)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                try:
                    self.proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    pass
        if self._reader:
            self._reader.join(timeout=2.0)

    def counters(self) -> dict:
        return {
            "packets_captured": self.packets_captured,
            "packets_dropped": self.packets_dropped,
            "last_error": self.last_error,
        }


class TcpdumpSource:
    name = "tcpdump"

    def __init__(
        self,
        interface: str,
        out_dir: Path,
        *,
        bpf: str | None = None,
        chunk_seconds: int = 5,
        base_name: str = "cap",
    ) -> None:
        self.interface = interface
        self.out_dir = Path(out_dir)
        self.bpf = bpf
        self.chunk_seconds = chunk_seconds
        self.base_name = base_name
        self.proc: subprocess.Popen | None = None
        self.packets_captured = 0
        self.packets_dropped = 0
        self.packets_received = 0
        self.last_error: str | None = None
        self._reader: threading.Thread | None = None

    @staticmethod
    def available() -> bool:
        return bool(shutil.which("tcpdump"))

    def start(self) -> None:
        binary = shutil.which("tcpdump")
        if not binary:
            raise SourceError("tcpdump not installed - run: sudo pacman -S tcpdump")
        self.out_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.out_dir, 0o700)
        target = self.out_dir / f"{self.base_name}.pcapng"
        cmd = [
            binary,
            "-i",
            self.interface,
            "-w",
            str(target),
            "-U",
            "-W",
            "10",
            "-C",
            "50",
        ]
        if self.bpf:
            cmd.append(self.bpf)
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        self._reader = threading.Thread(target=self._read_stderr, daemon=True)
        self._reader.start()
        try:
            code = self.proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            return
        stderr = ""
        if self.proc.stderr:
            try:
                stderr = self.proc.stderr.read()
            except OSError:
                stderr = ""
        if "permission" in stderr.lower():
            raise SourceError(
                "tcpdump requires elevated capture privileges; set "
                "'sudo setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)' "
                "or run through dumpcap instead"
            )
        raise SourceError(
            f"tcpdump exited immediately (code {code}): {stderr.strip()[:300]}"
        )

    def _read_stderr(self) -> None:
        assert self.proc is not None and self.proc.stderr is not None
        for line in self.proc.stderr:
            match = _TCPDUMP_CAPTURED_RE.search(line)
            if match:
                self.packets_captured = max(self.packets_captured, int(match.group(1)))
                continue
            match = _TCPDUMP_RECEIVED_RE.search(line)
            if match:
                self.packets_received = max(
                    self.packets_received, int(match.group(1))
                )
                continue
            match = _TCPDUMP_DROPPED_RE.search(line)
            if match:
                self.packets_dropped = max(self.packets_dropped, int(match.group(1)))
                continue
            line = line.strip()
            if line:
                self.last_error = line

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def returncode(self) -> int | None:
        return self.proc.poll() if self.proc else None

    def stop(self, timeout: float = 3.0) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.send_signal(signal.SIGINT)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                try:
                    self.proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    pass
        if self._reader:
            self._reader.join(timeout=2.0)

    def counters(self) -> dict:
        return {
            "packets_captured": self.packets_captured,
            "packets_dropped": self.packets_dropped,
            "packets_received": self.packets_received,
            "last_error": self.last_error,
        }
