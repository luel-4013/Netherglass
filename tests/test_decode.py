import shutil
from pathlib import Path

import pytest

from netherglass.capture.decode import iter_ek_packets, normalize_ek

from pcap_gen import sample_capture


def _ek(layers: dict, timestamp: str = "1700000000.5") -> dict:
    return {"timestamp": timestamp, "layers": layers}


def test_normalize_dns_over_udp() -> None:
    record = _ek(
        {
            "frame": {
                "frame_frame_number": ["1"],
                "frame_frame_time_epoch": ["1700000000.5"],
                "frame_frame_len": ["78"],
                "frame_frame_protocols": ["eth:ethertype:ip:udp:dns"],
            },
            "ip": {"ip_ip_src": ["10.0.0.5"], "ip_ip_dst": ["10.0.0.53"]},
            "udp": {"udp_udp_srcport": ["53210"], "udp_udp_dstport": ["53"]},
            "dns": {"dns_dns_qry_name": ["example.com"]},
        }
    )
    packet = normalize_ek(record["layers"], record["timestamp"])
    assert packet is not None
    assert packet["num"] == 1
    assert packet["src"] == "10.0.0.5"
    assert packet["dst"] == "10.0.0.53"
    assert packet["sport"] == 53210 and packet["dport"] == 53
    assert packet["proto"] == "dns"
    assert packet["info"] == "DNS query example.com"
    assert packet["length"] == 78
    assert packet["ts"] == 1700000000.5


def test_normalize_tls_client_hello() -> None:
    packet = normalize_ek(
        {
            "frame": {
                "frame_frame_number": ["2"],
                "frame_frame_time_epoch": ["1700000001.0"],
                "frame_frame_len": ["583"],
                "frame_frame_protocols": ["eth:ethertype:ip:tcp:tls"],
            },
            "ip": {"ip_ip_src": ["192.168.1.10"], "ip_ip_dst": ["93.184.216.34"]},
            "tcp": {
                "tcp_tcp_srcport": ["49152"],
                "tcp_tcp_dstport": ["443"],
                "tcp_tcp_flags_str": ["SYN"],
            },
            "tls": {"tls_tls_handshake_extensions_server_name": ["example.org"]},
        }
    )
    assert packet is not None
    assert packet["proto"] == "tls"
    assert "SNI=example.org" in packet["info"]


def test_normalize_nested_style_keys() -> None:
    packet = normalize_ek(
        {
            "frame": {
                "frame.number": "3",
                "frame.time_epoch": "1700000002.0",
                "frame.len": "74",
                "frame.protocols": "eth:ethertype:ip:tcp",
            },
            "ip": {"ip.src": "10.1.1.1", "ip.dst": "10.1.1.2"},
            "tcp": {"tcp.srcport": "1000", "tcp.dstport": "80"},
        }
    )
    assert packet is not None
    assert packet["src"] == "10.1.1.1"
    assert packet["dport"] == 80
    assert packet["proto"] == "tcp"


def test_epoch_iso_and_millisecond_formats() -> None:
    iso = normalize_ek(
        {
            "frame": {
                "frame_frame_protocols": "eth:ethertype:ip:udp:dns",
                "frame_frame_time_epoch": "2023-11-14T22:13:20.000000000Z",
            }
        }
    )
    assert iso is not None and abs((iso["ts"] or 0) - 1700000000.0) < 0.001
    millis = normalize_ek(
        {
            "frame": {
                "frame_frame_protocols": "eth:ethertype:ip:udp:dns",
                "frame_frame_time_epoch": ["1700000123000"],
            }
        }
    )
    assert millis is not None and abs((millis["ts"] or 0) - 1700000123.0) < 0.001


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
def test_real_tshark_decode_of_synthetic_pcap(tmp_path: Path) -> None:
    pcap = sample_capture(tmp_path / "sample.pcap")
    packets = list(iter_ek_packets(str(pcap)))
    assert len(packets) == 3
    protos = [p["proto"] for p in packets]
    assert protos == ["dns", "tcp", "icmp"]
    dns = packets[0]
    assert dns["src"] == "10.0.0.5"
    assert dns["dst"] == "10.0.0.53"
    assert dns["dport"] == 53
    assert "example.com" in (dns["info"] or "")
    assert abs((dns["ts"] or 0) - 1700000000.0) < 1.0
    tcp = packets[1]
    assert tcp["src"] == "192.168.1.10"
    assert tcp["dport"] == 443
    assert tcp["sport"] == 49152
    assert packets[2]["proto"] == "icmp"
