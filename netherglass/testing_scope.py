"""Controlled testing scope enforcement (spec sections 48, 52, 55).

Fail-closed rules:
- no scope file -> every test is refused;
- an assessment matches only inside its testing window and only for listed
  domains/CIDRs (exclusions always win);
- any parse/validation error refuses execution rather than guessing.

The scope file is ``<data_dir>/testing_scope.json`` and is maintained by the
operator out of band; it is never edited through the API.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SCOPE_FILENAME = "testing_scope.json"
MAX_ASSESSMENTS = 200


class ScopeError(ValueError):
    """Scope file missing or invalid (fail closed)."""


class ScopeViolation(ValueError):
    """Target does not match any active authorization."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value, field_name: str) -> datetime | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ScopeError(f"invalid {field_name}: {text!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _parse_cidrs(values, field_name: str) -> list[ipaddress._BaseNetwork]:
    networks = []
    for value in values or []:
        try:
            networks.append(ipaddress.ip_network(str(value), strict=False))
        except ValueError as exc:
            raise ScopeError(f"invalid {field_name} entry: {value!r}") from exc
    return networks


@dataclass
class Assessment:
    id: str
    name: str
    authorization_ref: str
    authorized_by: str
    domains: list[str] = field(default_factory=list)
    cidrs: list[ipaddress._BaseNetwork] = field(default_factory=list)
    excluded_cidrs: list[ipaddress._BaseNetwork] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    window_start: datetime | None = None
    window_end: datetime | None = None

    def active_at(self, when: datetime) -> bool:
        if self.window_start and when < self.window_start:
            return False
        if self.window_end and when > self.window_end:
            return False
        return True

    def matches_domain(self, host: str) -> bool:
        host = host.strip().lower().rstrip(".")
        for domain in self.domains:
            candidate = domain.strip().lower().rstrip(".")
            if not candidate:
                continue
            if host == candidate or host.endswith("." + candidate):
                return True
        return False

    def matches_ip(self, ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for network in self.excluded_cidrs:
            if address in network:
                return False
        return any(address in network for network in self.cidrs)

    def allows_port(self, port: int | None) -> bool:
        if not self.ports:
            return True
        return port in self.ports

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "authorization_ref": self.authorization_ref,
            "authorized_by": self.authorized_by,
            "domains": list(self.domains),
            "cidrs": [str(network) for network in self.cidrs],
            "excluded_cidrs": [str(network) for network in self.excluded_cidrs],
            "ports": list(self.ports),
            "window_start": self.window_start.isoformat()
            if self.window_start
            else None,
            "window_end": self.window_end.isoformat() if self.window_end else None,
            "active": self.active_at(_utcnow()),
        }


def scope_path(data_dir: Path) -> Path:
    return Path(data_dir) / SCOPE_FILENAME


def load_scope(data_dir: Path) -> list[Assessment]:
    path = scope_path(data_dir)
    if not path.is_file():
        raise ScopeError(
            f"no testing scope configured: create {path.name} with an "
            "'assessments' array before creating controlled tests"
        )
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ScopeError(f"testing scope unreadable: {exc}") from exc
    entries = raw.get("assessments") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise ScopeError("testing scope must contain an 'assessments' array")
    if len(entries) > MAX_ASSESSMENTS:
        raise ScopeError("too many assessments in testing scope")
    assessments: list[Assessment] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ScopeError(f"assessment #{index + 1} is not an object")
        auth_ref = str(entry.get("authorization_ref") or "").strip()
        if not auth_ref:
            raise ScopeError(
                f"assessment #{index + 1} has no authorization_ref (required)"
            )
        assessment = Assessment(
            id=str(entry.get("id") or auth_ref)[:120],
            name=str(entry.get("name") or auth_ref)[:200],
            authorization_ref=auth_ref[:200],
            authorized_by=str(entry.get("authorized_by") or "")[:200],
            domains=[str(d) for d in entry.get("domains") or []],
            cidrs=_parse_cidrs(entry.get("cidrs"), "cidrs"),
            excluded_cidrs=_parse_cidrs(entry.get("excluded_cidrs"), "excluded_cidrs"),
            ports=[int(p) for p in entry.get("ports") or []],
            window_start=_parse_time(entry.get("window_start"), "window_start"),
            window_end=_parse_time(entry.get("window_end"), "window_end"),
        )
        if not assessment.domains and not assessment.cidrs:
            raise ScopeError(
                f"assessment {assessment.id!r} lists no domains or cidrs; "
                "nothing would ever be authorized"
            )
        assessments.append(assessment)
    return assessments


def match_target(
    data_dir: Path,
    host: str,
    *,
    port: int | None = None,
    resolved_ips: list[str] | None = None,
    when: datetime | None = None,
) -> Assessment:
    """Return the matching active assessment or raise (fail closed)."""
    assessments = load_scope(data_dir)
    host = str(host or "").strip().lower().rstrip(".")
    if not host:
        raise ScopeViolation("target host is required")
    when = when or _utcnow()
    for assessment in assessments:
        if not assessment.active_at(when):
            continue
        if not assessment.allows_port(port):
            continue
        if assessment.matches_domain(host):
            return assessment
        if assessment.matches_ip(host):
            return assessment
        for ip in resolved_ips or []:
            if assessment.matches_ip(ip):
                return assessment
    reason = f"target {host!r}"
    if port is not None:
        reason += f":{port}"
    raise ScopeViolation(
        f"{reason} does not match any active authorized assessment "
        "(fail closed; check testing_scope.json windows/domains/cidrs)"
    )


def find_assessment(data_dir: Path, authorization_ref: str) -> Assessment:
    for assessment in load_scope(data_dir):
        if assessment.authorization_ref == authorization_ref or assessment.id == authorization_ref:
            return assessment
    raise ScopeViolation(
        f"authorization reference {authorization_ref!r} is not present in the "
        "testing scope"
    )


def scope_summary(data_dir: Path) -> dict:
    try:
        assessments = load_scope(data_dir)
    except ScopeError as exc:
        return {"configured": False, "error": str(exc), "assessments": []}
    return {
        "configured": True,
        "error": None,
        "assessments": [assessment.to_dict() for assessment in assessments],
    }
