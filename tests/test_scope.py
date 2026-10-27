import pytest

from netherglass.capture.scope import ScopeError, bpf_filter, check_interface
from netherglass.config import ScopeConfig


def test_no_scope_yields_no_filter_and_note() -> None:
    scope = ScopeConfig()
    bpf, notes = bpf_filter(scope)
    assert bpf is None
    assert any("no scope filters" in note for note in notes)


def test_allowed_cidrs_and_ports() -> None:
    scope = ScopeConfig(allowed_cidrs=["10.0.0.0/8"], allowed_ports=[443, "8000-8080"])
    bpf, notes = bpf_filter(scope)
    assert bpf is not None
    assert "net 10.0.0.0/8" in bpf
    assert "port 443" in bpf
    assert "portrange 8000-8080" in bpf
    assert bpf == "((net 10.0.0.0/8) or (port 443 or portrange 8000-8080))"
    assert notes == []


def test_exclusions_are_negated() -> None:
    scope = ScopeConfig(excluded_cidrs=["192.168.0.0/16"], excluded_ports=[22])
    bpf, _ = bpf_filter(scope)
    assert bpf is not None
    assert "not (net 192.168.0.0/16)" in bpf
    assert "not (port 22)" in bpf


def test_operator_filter_is_conjoined() -> None:
    scope = ScopeConfig(allowed_cidrs=["10.0.0.0/8"])
    bpf, _ = bpf_filter(scope, extra="tcp port 80")
    assert bpf == "(net 10.0.0.0/8) and (tcp port 80)"


def test_invalid_cidr_raises() -> None:
    scope = ScopeConfig(allowed_cidrs=["10.0.0.0/33"])
    with pytest.raises(ScopeError):
        bpf_filter(scope)


def test_invalid_port_raises() -> None:
    scope = ScopeConfig(allowed_ports=[999999])
    with pytest.raises(ScopeError):
        bpf_filter(scope)


def test_ipv6_cidr_produces_note() -> None:
    scope = ScopeConfig(allowed_cidrs=["2001:db8::/32"])
    bpf, notes = bpf_filter(scope)
    assert bpf is not None and "ip6" in bpf
    assert any("IPv6" in note for note in notes)


def test_interface_allow_and_deny() -> None:
    scope = ScopeConfig(allowed_interfaces=["wlo1"], excluded_interfaces=["eno1"])
    check_interface(scope, "wlo1")
    with pytest.raises(ScopeError):
        check_interface(scope, "eth0")
    scope2 = ScopeConfig(excluded_interfaces=["eno1"])
    with pytest.raises(ScopeError):
        check_interface(scope2, "eno1")
