"""Capture scope enforcement: interface allow/deny plus BPF filter building.

Rules (spec section 22/25):
- Scope is enforced before capture starts and again as a kernel-level BPF
  filter, so out-of-scope traffic is not written to disk in the first place.
- Both are fail-closed: invalid scope refuses to start the capture.
- IPv6 CIDRs are reported as unsupported for BPF (libpcap support varies) and
  are surfaced to the operator instead of being silently dropped.
"""

from __future__ import annotations

import ipaddress
import re

from ..config import ScopeConfig

_PORT_RE = re.compile(r"^\d{1,5}$")


class ScopeError(ValueError):
    """Raised when a capture request violates or cannot express the scope."""


def check_interface(scope: ScopeConfig, interface: str) -> None:
    if scope.allowed_interfaces and interface not in scope.allowed_interfaces:
        raise ScopeError(
            f"interface '{interface}' is not in allowed_interfaces "
            f"({', '.join(scope.allowed_interfaces)})"
        )
    if interface in scope.excluded_interfaces:
        raise ScopeError(f"interface '{interface}' is excluded by scope")


def _cidr_clause(cidr: str) -> tuple[str, str | None]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ScopeError(f"invalid CIDR in scope: {cidr!r} ({exc})") from exc
    if net.version == 4:
        return f"net {net.with_prefixlen}", None
    return (
        f"(ip6 and net {net.with_prefixlen})",
        f"IPv6 CIDR {net.with_prefixlen} compiled to 'ip6 net'; verify with "
        "your libpcap version, otherwise use interface-level scope",
    )


def _ports_clause(ports: list[int] | list[str]) -> str:
    parts: list[str] = []
    for port in ports:
        text = str(port).strip()
        if "-" in text:
            lo, _, hi = text.partition("-")
            if not (_PORT_RE.match(lo) and _PORT_RE.match(hi)):
                raise ScopeError(f"invalid port range in scope: {text!r}")
            parts.append(f"portrange {lo}-{hi}")
        elif _PORT_RE.match(text) and 0 < int(text) <= 65535:
            parts.append(f"port {int(text)}")
        else:
            raise ScopeError(f"invalid port in scope: {text!r}")
    return " or ".join(parts)


def bpf_filter(
    scope: ScopeConfig, *, extra: str | None = None
) -> tuple[str | None, list[str]]:
    """Build a BPF filter from scope and an optional operator override.

    Returns (filter or None, notes). None means "no filter" (all traffic).
    """
    notes: list[str] = []
    include_parts: list[str] = []
    exclude_parts: list[str] = []

    for cidr in scope.allowed_cidrs:
        clause, note = _cidr_clause(cidr)
        include_parts.append(clause)
        if note:
            notes.append(note)
    for cidr in scope.excluded_cidrs:
        clause, note = _cidr_clause(cidr)
        exclude_parts.append(clause)
        if note:
            notes.append(note)
    if scope.allowed_ports:
        include_parts.append(_ports_clause(scope.allowed_ports))
    if scope.excluded_ports:
        exclude_parts.append(_ports_clause(scope.excluded_ports))

    parts: list[str] = []
    include = " or ".join(f"({p})" for p in include_parts)
    if include_parts and len(include_parts) > 1:
        include = f"({include})"
    if include_parts:
        parts.append(include)
    for clause in exclude_parts:
        parts.append(f"not ({clause})")

    operator = (extra or "").strip()
    if operator:
        parts.append(f"({operator})")

    if not parts:
        notes.append(
            "no scope filters configured: capturing all traffic visible on the "
            "interface; consider configuring scope for authorized-testing hygiene"
        )
        return None, notes
    return " and ".join(parts), notes
