"""Decode capture files with tshark (EK JSON) into normalized packet records.

Streaming contract: `iter_ek_packets` spawns tshark per file and yields one
normalized dict per packet, so memory stays flat regardless of PCAP size.
Normalization is intentionally lossy: we keep the fields the platform needs
(5-tuple, protocol, info) and never copy payload contents into the database
(sensitive values belong in the encrypted vault, not the search index).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from ..analysis import protocols, sensitive

_FRACTION_RE = re.compile(r"(\.\d{6})\d+")

INTERESTING_PROTOCOLS = (
    "dns",
    "http",
    "tls",
    "quic",
    "icmp",
    "icmpv6",
    "arp",
    "dhcp",
    "ssh",
    "ftp",
    "smtp",
    "smb",
    "kerberos",
)


class DecodeError(RuntimeError):
    pass


def tshark_path() -> str | None:
    return shutil.which("tshark")


def _first(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _as_epoch(value: Any) -> float | None:
    """Accept seconds, milliseconds, or ISO-8601 (with Z / nanoseconds)."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        number = float(text)
    except ValueError:
        normalized = _FRACTION_RE.sub(r"\1", text).replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(normalized).timestamp()
        except ValueError:
            return None
    if number > 1e11:  # EK's "timestamp" field is milliseconds since epoch
        number /= 1000.0
    return number


_MULTI_VALUE_KEYS = {
    "http_http_response_line",
    "http_response_line",
    "http_http_set_cookie",
    "http_set_cookie",
    "http_http_cookie",
    "http_cookie",
}


def _flatten(layers: dict, prefix: str, out: dict[str, Any]) -> None:
    for key, value in layers.items():
        if isinstance(value, dict):
            _flatten(value, key, out)
        elif isinstance(value, list) and value and isinstance(value[0], dict):
            _flatten(value[0], key, out)
        else:
            if key in _MULTI_VALUE_KEYS and isinstance(value, list):
                out.setdefault(key, list(value))
                continue
            out.setdefault(key, _first(value))
            normalized = key.replace(".", "_")
            if normalized != key:
                out.setdefault(normalized, _first(value))


def _get(fields: dict[str, Any], *candidates: str) -> Any:
    for key in candidates:
        if key in fields:
            return fields[key]
    return None


def _as_int(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _build_info(fields: dict[str, Any], proto: str) -> str:
    dns_name = _get(fields, "dns_dns_qry_name", "dns_qry_name")
    if dns_name:
        return f"DNS query {dns_name}"
    method = _get(fields, "http_http_request_method", "http_request_method")
    if method:
        host = _get(fields, "http_http_host", "http_host") or ""
        uri = _get(fields, "http_http_request_uri", "http_request_uri") or ""
        path, query_names = protocols.sanitize_http_path(str(uri))
        shown = protocols.http_display_uri(
            str(host) if host else None, path, bool(query_names)
        )
        return f"HTTP {method} {shown}".strip()
    code = _get(fields, "http_http_response_code", "http_response_code")
    if code:
        return f"HTTP response {code}"
    sni = _get(
        fields,
        "tls_tls_handshake_extensions_server_name",
        "tls_handshake_extensions_server_name",
    )
    if sni:
        return f"TLS ClientHello SNI={sni}"
    if proto == "arp":
        src = _get(fields, "arp_arp_src_proto_ipv4", "arp_src_proto_ipv4") or "?"
        dst = _get(fields, "arp_arp_dst_proto_ipv4", "arp_dst_proto_ipv4") or "?"
        opcode = _get(fields, "arp_arp_opcode", "arp_opcode")
        kind = "request" if opcode == "1" else "reply" if opcode == "2" else opcode
        return f"ARP {kind} {src} -> {dst}"
    if proto in ("icmp", "icmpv6"):
        kind = _get(fields, "icmp_icmp_type", "icmp_type") or _get(
            fields, "icmpv6_icmpv6_type", "icmpv6_type"
        )
        return f"ICMP type={kind}".strip()
    hostname = _get(fields, "dhcp_dhcp_option_hostname", "dhcp_option_hostname")
    if hostname:
        return f"DHCP host {hostname}"
    ports = ""
    sport = _get(fields, "tcp_tcp_srcport", "tcp_srcport")
    dport = _get(fields, "tcp_tcp_dstport", "tcp_dstport")
    if sport is None:
        sport = _get(fields, "udp_udp_srcport", "udp_srcport")
        dport = _get(fields, "udp_udp_dstport", "udp_dstport")
    if sport is not None and dport is not None:
        ports = f" {sport} -> {dport}"
    flags = _get(fields, "tcp_tcp_flags_str", "tcp_flags_str")
    flag_text = f" [{flags}]" if flags else ""
    return f"{proto.upper()}{ports}{flag_text}".strip()


def normalize_ek(
    layers: dict[str, Any],
    timestamp: str | None = None,
    patterns: list[dict] | None = None,
) -> dict | None:
    if not isinstance(layers, dict):
        return None
    fields: dict[str, Any] = {}
    _flatten(layers, "", fields)

    protocols_raw = _get(fields, "frame_frame_protocols", "frame_protocols") or ""
    layer_names = [p for p in str(protocols_raw).split(":") if p]
    proto_chain = [p for p in layer_names if p not in ("eth", "ethertype")]
    top_proto = None
    for candidate in reversed(proto_chain):
        if candidate in INTERESTING_PROTOCOLS or candidate in ("tcp", "udp"):
            top_proto = candidate
            break
    if top_proto is None:
        top_proto = proto_chain[-1] if proto_chain else "unknown"

    src = _get(fields, "ip_ip_src", "ip_src") or _get(
        fields, "ipv6_ipv6_src", "ipv6_src"
    )
    dst = _get(fields, "ip_ip_dst", "ip_dst") or _get(
        fields, "ipv6_ipv6_dst", "ipv6_dst"
    )
    if _get(fields, "arp_arp_opcode", "arp_opcode"):
        src = src or _get(fields, "arp_arp_src_proto_ipv4", "arp_src_proto_ipv4")
        dst = dst or _get(fields, "arp_arp_dst_proto_ipv4", "arp_dst_proto_ipv4")

    sport = _as_int(_get(fields, "tcp_tcp_srcport", "tcp_srcport"))
    dport = _as_int(_get(fields, "tcp_tcp_dstport", "tcp_dstport"))
    if sport is None:
        sport = _as_int(_get(fields, "udp_udp_srcport", "udp_srcport"))
        dport = _as_int(_get(fields, "udp_udp_dstport", "udp_dstport"))
    if sport is None:
        sport = _as_int(_get(fields, "sctp_sctp_srcport", "sctp_srcport"))
        dport = _as_int(_get(fields, "sctp_sctp_dstport", "sctp_dstport"))

    ts = _as_epoch(_get(fields, "frame_frame_time_epoch", "frame_time_epoch"))
    if ts is None:
        ts = _as_epoch(timestamp)

    packet = {
        "num": _as_int(_get(fields, "frame_frame_number", "frame_number")),
        "ts": ts,
        "src": src,
        "dst": dst,
        "sport": sport,
        "dport": dport,
        "proto": top_proto,
        "length": _as_int(_get(fields, "frame_frame_len", "frame_len")),
        "info": _build_info(fields, top_proto),
    }
    packet["_layers"] = proto_chain
    protocols.enrich(fields, packet)
    packet["_sensitive"] = sensitive.collect_candidates(fields, packet, patterns)
    return packet

def iter_ek_packets(
    pcap_file: str,
    tshark: str | None = None,
    patterns: list[dict] | None = None,
) -> Iterator[dict]:
    binary = tshark or tshark_path()
    if not binary:
        raise DecodeError("tshark not found; install wireshark-cli")
    proc = subprocess.Popen(
        [binary, "-r", pcap_file, "-T", "ek", "-n"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            layers = record.get("layers")
            if not isinstance(layers, dict):
                continue
            packet = normalize_ek(layers, record.get("timestamp"), patterns)
            if packet is not None:
                yield packet
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            stderr = proc.stderr.read() if proc.stderr else ""
        except OSError:
            stderr = ""
        code = proc.wait(timeout=10)
        if code not in (0, -15) and not stderr.strip().startswith("Running as user"):
            raise DecodeError(
                f"tshark exited with code {code}: {stderr.strip()[:300]}"
            )


def iter_tls_certificates(pcap_file: str, tshark: str | None = None) -> list[dict]:
    """Second targeted pass for certificate SANs (unavailable in EK flat form).

    Returns [{stream, frame, sans, name_strings}]. Values are display names;
    private keys and payload bytes are never extracted.
    """
    binary = tshark or tshark_path()
    if not binary:
        raise DecodeError("tshark not found; install wireshark-cli")
    proc = subprocess.run(
        [
            binary,
            "-r",
            pcap_file,
            "-Y",
            "tls.handshake.type==11",
            "-T",
            "fields",
            "-e",
            "tcp.stream",
            "-e",
            "frame.number",
            "-e",
            "x509ce.dNSName",
            "-e",
            "x509sat.printableString",
            "-e",
            "x509sat.uTF8String",
            "-n",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if proc.returncode not in (0, -15) and not proc.stderr.strip().startswith(
        "Running as user"
    ):
        raise DecodeError(
            f"tshark certificate pass failed: {proc.stderr.strip()[:300]}"
        )
    records: list[dict] = []
    for line in proc.stdout.splitlines():
        columns = line.split("\t")
        while len(columns) < 5:
            columns.append("")
        stream, frame, sans, printable, utf8 = columns[:5]
        name_strings = [
            item.strip()
            for item in (printable + "," + utf8).split(",")
            if item.strip()
        ]
        sans_list = [item.strip() for item in sans.split(",") if item.strip()]
        records.append(
            {
                "stream": stream.strip() or None,
                "frame": _as_int(frame),
                "sans": sans_list,
                "name_strings": name_strings,
            }
        )
    return records
