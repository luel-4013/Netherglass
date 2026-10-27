"""Build minimal synthetic PCAP files byte-by-byte.

This lets tests exercise the real tshark decode path without capture
privileges or the network. No scapy dependency.
"""

from __future__ import annotations

import struct
from pathlib import Path

ETH_IPV4 = 0x0800


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4_header(src: str, dst: str, proto: int, payload_len: int) -> bytes:
    total_len = 20 + payload_len
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0x1234,
        0x4000,
        64,
        proto,
        0,
        bytes(int(o) for o in src.split(".")),
        bytes(int(o) for o in dst.split(".")),
    )
    csum = _checksum(header)
    return header[:10] + struct.pack("!H", csum) + header[12:]


def _ethernet(payload: bytes) -> bytes:
    dst = bytes.fromhex("aabbccddeeff")
    src = bytes.fromhex("001122334455")
    return dst + src + struct.pack("!H", ETH_IPV4) + payload


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload


def _dns_query(name: str) -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", 1, 1)


def dns_query_packet(src: str, dst: str, name: str) -> bytes:
    dns = _dns_query(name)
    ip = _ipv4_header(src, dst, 17, 8 + len(dns))
    return _ethernet(ip + _udp(53210, 53, dns))


def tcp_syn_packet(src: str, dst: str, sport: int, dport: int) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, 0x02, 64240, 0, 0)
    ip = _ipv4_header(src, dst, 6, len(tcp))
    return _ethernet(ip + tcp)


def icmp_echo_packet(src: str, dst: str) -> bytes:
    body = struct.pack("!HH", 1, 1) + b"netherglass"
    icmp = struct.pack("!BBH", 8, 0, 0) + body
    csum = _checksum(icmp)
    icmp = struct.pack("!BBH", 8, 0, csum) + body
    ip = _ipv4_header(src, dst, 1, len(icmp))
    return _ethernet(ip + icmp)


def write_pcap(path: Path, frames: list[bytes], base_ts: int = 1_700_000_000) -> Path:
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            ts = base_ts + index
            handle.write(struct.pack("<IIII", ts, 0, len(frame), len(frame)))
            handle.write(frame)
    return path


def sample_capture(path: Path) -> Path:
    frames = [
        dns_query_packet("10.0.0.5", "10.0.0.53", "example.com"),
        tcp_syn_packet("192.168.1.10", "93.184.216.34", 49152, 443),
        icmp_echo_packet("192.168.1.10", "8.8.8.8"),
    ]
    return write_pcap(path, frames)
