from netherglass.interfaces import capture_readiness, classify_interface, discover_interfaces


def test_classify_wifi_by_wireless_dir() -> None:
    assert classify_interface("wlo1", 1, True) == "wifi"


def test_classify_wifi_by_name() -> None:
    assert classify_interface("wlan0", 1, False) == "wifi"


def test_classify_ethernet() -> None:
    assert classify_interface("eno1", 1, False) == "ethernet"
    assert classify_interface("enp3s0", 1, False) == "ethernet"


def test_classify_loopback() -> None:
    assert classify_interface("lo", 772, False) == "loopback"


def test_classify_virtual() -> None:
    assert classify_interface("veth1234", 1, False) == "virtual"
    assert classify_interface("vboxnet0", 1, False) == "virtual"
    assert classify_interface("tun0", 1, False) == "virtual"


def test_classify_unknown_type() -> None:
    assert classify_interface("mystery9", 65534, False) == "unknown"


def test_discover_includes_loopback() -> None:
    names = {i.name for i in discover_interfaces()}
    assert "lo" in names or not names


def test_readiness_structure() -> None:
    report = capture_readiness()
    ids = {s["id"] for s in report["sources"]}
    assert {"dumpcap", "tshark", "tcpdump", "scapy", "offline"} <= ids
    offline = [s for s in report["sources"] if s["id"] == "offline"][0]
    assert offline["available"] is True
    assert isinstance(report["packet_socket"], bool)
    assert isinstance(report["hints"], list)
