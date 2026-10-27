"""Network interface discovery, classification and capture-source readiness.

Honesty rules (spec section 4 and 6):
- Wi-Fi interfaces in managed mode only see this host's traffic plus broadcast
  and multicast. The UI labels this instead of pretending otherwise.
- Readiness never claims capture is possible when the privileges, tools or
  libraries are missing.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import socket
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

SYSFS_NET = Path("/sys/class/net")

ARPHRD_ETHER = 1
ARPHRD_LOOPBACK = 772

WIFI_PREFIXES = ("wlan", "wlp", "wlo", "wlx", "wifi", "ath", "ra")
VIRTUAL_PREFIXES = (
    "veth",
    "docker",
    "br-",
    "virbr",
    "tun",
    "tap",
    "wg",
    "vboxnet",
    "vmnet",
    "dummy",
    "bond",
)


@dataclass
class InterfaceInfo:
    name: str
    kind: str
    operstate: str
    mac: str | None
    mtu: int | None
    addresses: list[str]
    wireless: bool
    notes: str


def classify_interface(name: str, type_num: int, has_wireless_dir: bool) -> str:
    if name == "lo" or type_num == ARPHRD_LOOPBACK:
        return "loopback"
    if has_wireless_dir or name.startswith(WIFI_PREFIXES):
        return "wifi"
    if name.startswith(VIRTUAL_PREFIXES):
        return "virtual"
    if type_num == ARPHRD_ETHER:
        return "ethernet"
    return "unknown"


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except OSError:
        return None


def _addresses_from_ip() -> dict[str, list[str]]:
    ip_bin = shutil.which("ip")
    if not ip_bin:
        return {}
    try:
        result = subprocess.run(
            [ip_bin, "-j", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        data = json.loads(result.stdout)
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}
    addresses: dict[str, list[str]] = {}
    for entry in data:
        name = entry.get("ifname")
        if not name:
            continue
        addrs: list[str] = []
        for info in entry.get("addr_info", []):
            local = info.get("local")
            if not local:
                continue
            if info.get("family") == "inet" and info.get("prefixlen") is not None:
                local = f"{local}/{info['prefixlen']}"
            addrs.append(local)
        addresses[name] = addrs
    return addresses


def discover_interfaces(sysfs: Path = SYSFS_NET) -> list[InterfaceInfo]:
    addresses = _addresses_from_ip()
    found: list[InterfaceInfo] = []
    if not sysfs.exists():
        return found
    for entry in sorted(sysfs.iterdir()):
        name = entry.name
        type_raw = _read_text(entry / "type")
        try:
            type_num = int(type_raw, 16) if type_raw else 0
        except ValueError:
            type_num = 0
        has_wireless = (entry / "wireless").is_dir()
        kind = classify_interface(name, type_num, has_wireless)
        operstate = _read_text(entry / "operstate") or "unknown"
        mac = _read_text(entry / "address")
        mtu_raw = _read_text(entry / "mtu")
        notes = ""
        if kind == "wifi":
            notes = (
                "Wi-Fi in managed mode: captures this host's traffic and "
                "broadcast/multicast only."
            )
        elif kind == "virtual":
            notes = (
                "Virtual interface: visibility depends on the virtual network "
                "configuration."
            )
        found.append(
            InterfaceInfo(
                name=name,
                kind=kind,
                operstate=operstate,
                mac=mac,
                mtu=int(mtu_raw) if mtu_raw and mtu_raw.isdigit() else None,
                addresses=addresses.get(name, []),
                wireless=has_wireless,
                notes=notes,
            )
        )
    return found


def _dumpcap_capability(dumpcap_path: str) -> bool | None:
    getcap = shutil.which("getcap")
    if not getcap:
        return None
    try:
        result = subprocess.run(
            [getcap, dumpcap_path],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return "cap_net_raw" in result.stdout


def packet_socket_possible() -> bool:
    try:
        probe = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        probe.close()
        return True
    except (PermissionError, OSError):
        return False


def capture_readiness() -> dict:
    found = {
        tool: shutil.which(tool, mode=os.F_OK)
        for tool in ("dumpcap", "tshark", "tcpdump")
    }
    scapy_available = importlib.util.find_spec("scapy") is not None
    can_raw = packet_socket_possible()

    dumpcap_path = found["dumpcap"]
    dumpcap_runnable = bool(dumpcap_path) and os.access(dumpcap_path, os.X_OK)
    if dumpcap_path and not dumpcap_runnable:
        dumpcap_detail = (
            f"installed at {dumpcap_path} but not executable by this user; "
            "run: sudo usermod -aG wireshark $USER, then log out and back in"
        )
        dumpcap_available = False
    elif dumpcap_path:
        caps = _dumpcap_capability(dumpcap_path)
        dumpcap_available = True
        if caps is None:
            dumpcap_detail = f"found at {dumpcap_path}"
        elif caps:
            dumpcap_detail = f"found at {dumpcap_path} (capture capability present)"
        else:
            dumpcap_detail = f"found at {dumpcap_path} (wireshark group access)"
    else:
        dumpcap_available = False
        dumpcap_detail = "not installed - run: sudo pacman -S wireshark-cli"

    scapy_detail = "installed" if scapy_available else (
        "not installed - run: .venv/bin/pip install scapy"
    )
    scapy_detail += (
        "; raw socket permission granted"
        if can_raw
        else "; raw socket permission missing (CAP_NET_RAW)"
    )

    tshark_runnable = bool(found["tshark"]) and os.access(found["tshark"], os.X_OK)
    tcpdump_runnable = bool(found["tcpdump"]) and os.access(found["tcpdump"], os.X_OK)

    sources = [
        {
            "id": "dumpcap",
            "label": "Live capture via Wireshark dumpcap",
            "available": dumpcap_available,
            "detail": dumpcap_detail,
        },
        {
            "id": "tshark",
            "label": "Protocol decode via tshark",
            "available": tshark_runnable,
            "detail": (
                f"found at {found['tshark']}"
                if tshark_runnable
                else "not installed - run: sudo pacman -S wireshark-cli"
            ),
        },
        {
            "id": "tcpdump",
            "label": "Fallback capture via tcpdump",
            "available": tcpdump_runnable,
            "detail": (
                f"found at {found['tcpdump']}"
                if tcpdump_runnable
                else "not installed - run: sudo pacman -S tcpdump"
            ),
        },
        {
            "id": "scapy",
            "label": "Fallback capture/decode via Python Scapy",
            "available": scapy_available and can_raw,
            "detail": scapy_detail,
        },
        {
            "id": "offline",
            "label": "Offline PCAP/PCAPNG import",
            "available": True,
            "detail": "always available - no privileges required",
        },
    ]

    hints: list[str] = []
    if not (dumpcap_available or tcpdump_runnable or (scapy_available and can_raw)):
        if dumpcap_path and not dumpcap_runnable:
            hints.append(
                "dumpcap is installed but this user cannot execute it. Run: "
                "sudo usermod -aG wireshark $USER, then log out and back in "
                "(or 'newgrp wireshark' for the current shell)."
            )
        else:
            hints.append(
                "Live capture is not ready. Recommended: sudo pacman -S wireshark-cli "
                "(installs dumpcap and tshark), then re-run 'netherglass doctor'."
            )
    return {"sources": sources, "packet_socket": can_raw, "hints": hints}


def interfaces_as_dicts() -> list[dict]:
    return [asdict(info) for info in discover_interfaces()]
