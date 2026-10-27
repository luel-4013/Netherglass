"""Sensitive-data detection engine (spec sections 16-18, 61).

Contract: this module only *classifies and collects* candidate artifacts from
in-memory decoded fields. It never writes anything to disk or the database;
callers must seal values through the evidence vault. Values never appear in
logs, audit events, findings or ordinary tables.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

JWT_CLAIM_METADATA = ("iss", "sub", "aud", "iat", "exp", "nbf", "jti", "scope")

MAX_VALUE = 512
MAX_CANDIDATES = 32
MAX_COOKIE_PAIRS = 8

JWT_RE = r"^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$"
AWS_KEY_RE = r"^AKIA[0-9A-Z]{16}$"
GITHUB_TOKEN_RE = r"^(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}$"
SLACK_TOKEN_RE = r"^xox[baprs]-[A-Za-z0-9-]{10,}$"
STRIPE_KEY_RE = r"^(sk|pk)_(live|test)_[A-Za-z0-9]{16,}$"
PRIVATE_KEY_RE = r"-----BEGIN [A-Z ]*PRIVATE KEY-----"

DEFAULT_PATTERNS: list[tuple[str, str, str]] = [
    ("JWT", "jwt", JWT_RE),
    ("CLOUD_CREDENTIAL", "aws_access_key", AWS_KEY_RE),
    ("API_KEY", "github_token", GITHUB_TOKEN_RE),
    ("API_KEY", "slack_token", SLACK_TOKEN_RE),
    ("API_KEY", "stripe_key", STRIPE_KEY_RE),
    ("PRIVATE_KEY", "private_key", PRIVATE_KEY_RE),
]

PASSWORD_KEYS = {
    "password",
    "passwd",
    "pass",
    "pwd",
    "pin",
    "passphrase",
    "secret",
}
USERNAME_KEYS = {"user", "username", "login", "uname", "account", "userid"}
EMAIL_KEYS = {"email", "mail", "e-mail"}

SESSION_COOKIE_NAMES = {
    "phpsessid",
    "jsessionid",
    "asp.net_sessionid",
    "connect.sid",
    "sessionid",
    "sid",
    "sess",
}
AUTH_COOKIE_MARKERS = ("auth", "sso", "login")
TOKEN_COOKIE_MARKERS = ("token", "bearer", "access")
CSRF_COOKIE_MARKERS = ("csrf", "xsrf")


_DEFAULT_COMPILED: list[dict] = [
    {"name": name, "type": type_, "regex": re.compile(regex)}
    for type_, name, regex in DEFAULT_PATTERNS
]


class PatternError(ValueError):
    pass


def load_patterns(data_dir: Path | None = None) -> list[dict]:
    """Defaults plus operator-defined rules.json custom patterns.

    rules.json format: {"custom_patterns": [{"name": ..., "type": ..., "regex": ...}]}
    """
    custom: list[dict] = []
    if data_dir is not None:
        path = Path(data_dir) / "rules.json"
        if path.is_file():
            try:
                raw = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError):
                raw = {}
            for entry in raw.get("custom_patterns") or []:
                if not isinstance(entry, dict):
                    continue
                regex = entry.get("regex")
                if not regex:
                    continue
                try:
                    compiled = re.compile(str(regex))
                except re.error as exc:
                    raise PatternError(f"invalid custom pattern {regex!r}: {exc}") from exc
                custom.append(
                    {
                        "name": str(entry.get("name") or "custom"),
                        "type": str(entry.get("type") or "UNKNOWN_SECRET"),
                        "regex": compiled,
                    }
                )
    return custom + list(_DEFAULT_COMPILED)


def _get(fields: dict[str, Any], *candidates: str) -> Any:
    for key in candidates:
        if key in fields:
            return fields[key]
    return None


def _headers(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    return [text] if text else []


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _refine_type(kind: str | None, value: str, patterns: list[dict]) -> str:
    for pattern in patterns:
        if pattern["regex"].search(value):
            return str(pattern["type"])
    return kind or "UNKNOWN_SECRET"


def _name_kind(name: str, *, cookie: bool) -> str | None:
    lowered = name.strip().lower()
    if "refresh" in lowered:
        return "REFRESH_TOKEN"
    if "csrf" in lowered or "xsrf" in lowered:
        return "CSRF_TOKEN"
    if "oauth" in lowered or "saml" in lowered or lowered == "sso":
        return "OAUTH_ARTIFACT"
    if "jwt" in lowered:
        return "JWT"
    if "apikey" in lowered or "api_key" in lowered or "api-key" in lowered:
        return "API_KEY"
    if cookie:
        if lowered in SESSION_COOKIE_NAMES or "session" in lowered:
            return "SESSION_COOKIE"
        if any(marker in lowered for marker in CSRF_COOKIE_MARKERS):
            return "CSRF_TOKEN"
        if any(marker in lowered for marker in AUTH_COOKIE_MARKERS):
            return "AUTH_COOKIE"
        if any(marker in lowered for marker in TOKEN_COOKIE_MARKERS):
            return "ACCESS_TOKEN"
        return None
    if "session" in lowered or lowered in ("sid", "sess"):
        return "ACCESS_TOKEN"
    if lowered in ("token", "auth", "bearer", "access_token", "id_token"):
        return "ACCESS_TOKEN"
    return None


def _b64url_json(segment: str) -> dict | None:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def jwt_metadata(value: str) -> dict | None:
    """Extract non-secret JWT metadata (alg/kid, selected claims).

    Runs entirely in memory; the token itself is never stored here. Claim
    values are kept only for identity/time fields, and only as short strings.
    """
    parts = value.split(".")
    if len(parts) != 3:
        return None
    header = _b64url_json(parts[0])
    if header is None:
        return None
    payload = _b64url_json(parts[1]) or {}
    claims: dict[str, Any] = {}
    for name in JWT_CLAIM_METADATA:
        if name not in payload:
            continue
        raw = payload[name]
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            claims[name] = raw
        elif isinstance(raw, str):
            claims[name] = raw[:256]
        elif isinstance(raw, list) and all(isinstance(item, str) for item in raw):
            claims[name] = [item[:256] for item in raw[:8]]
    alg = header.get("alg")
    kid = header.get("kid")
    return {
        "alg": str(alg)[:32] if alg is not None else None,
        "kid": str(kid)[:128] if kid is not None else None,
        "typ": str(header.get("typ"))[:32] if header.get("typ") else None,
        "claims": claims,
    }


class _Collector:
    def __init__(self, patterns: list[dict]) -> None:
        self.patterns = patterns
        self.items: dict[tuple[str, str], dict] = {}

    def add(
        self,
        kind: str | None,
        field: str,
        value: str | None,
        *,
        source: str,
        meta: dict | None = None,
        confidence: str = "OBSERVED",
    ) -> None:
        if value is None:
            return
        cleaned = value.strip()
        if not cleaned or len(cleaned) > MAX_VALUE:
            return
        final = _refine_type(kind, cleaned, self.patterns)
        key = (final, cleaned)
        if key in self.items or len(self.items) >= MAX_CANDIDATES:
            return
        details = dict(meta or {})
        if final == "JWT":
            extracted = jwt_metadata(cleaned)
            if extracted:
                details["jwt"] = extracted
        self.items[key] = {
            "type": final,
            "field": field,
            "value": cleaned,
            "source": source,
            "confidence": confidence,
            "meta": details,
        }


def _parse_pairs(header: str, *, limit: int) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for chunk in header.split(";"):
        if "=" not in chunk:
            continue
        name, _, value = chunk.partition("=")
        name, value = name.strip(), value.strip()
        if not name:
            continue
        pairs.append((name, value))
        if len(pairs) >= limit:
            break
    return pairs


def _cookie_attributes(header: str) -> dict:
    attributes: dict[str, str | bool] = {}
    for chunk in header.split(";")[1:]:
        part = chunk.strip()
        if not part:
            continue
        name, _, value = part.partition("=")
        name, value = name.strip(), value.strip()
        lowered = name.lower()
        if lowered in ("secure", "httponly"):
            attributes[name] = True
        elif lowered in ("samesite", "domain", "path", "expires", "max-age") and value:
            attributes[name] = value[:128]
    return attributes


def collect_candidates(
    fields: dict[str, Any],
    packet: dict[str, Any],
    patterns: list[dict] | None = None,
) -> list[dict]:
    patterns = patterns if patterns is not None else list(_DEFAULT_COMPILED)
    collector = _Collector(patterns)
    is_http = (packet.get("app_proto") or packet.get("proto") or "").lower() == "http"

    if is_http:
        authorization = _text(
            _get(fields, "http_http_authorization", "http_authorization")
        )
        if authorization:
            scheme, _, credential = authorization.partition(" ")
            scheme = scheme.strip()
            credential = credential.strip()
            if scheme.lower() == "basic" and credential:
                try:
                    decoded = base64.b64decode(credential, validate=True).decode(
                        "utf-8", errors="replace"
                    )
                except (ValueError, TypeError):
                    decoded = None
                if decoded and ":" in decoded:
                    username, _, _password = decoded.partition(":")
                    collector.add(
                        "BASIC_AUTH",
                        "Authorization: Basic",
                        decoded,
                        source="http.authorization",
                        meta={"username": username[:128]},
                    )
                elif decoded:
                    collector.add(
                        "UNKNOWN_SECRET",
                        "Authorization: Basic",
                        decoded,
                        source="http.authorization",
                    )
            elif scheme.lower() == "bearer" and credential:
                kind = "JWT" if re.match(JWT_RE, credential) else "BEARER_TOKEN"
                collector.add(
                    kind,
                    "Authorization: Bearer",
                    credential,
                    source="http.authorization",
                )
            elif credential:
                collector.add(
                    "UNKNOWN_SECRET",
                    f"Authorization: {scheme or 'unknown'}",
                    credential,
                    source="http.authorization",
                )

        cookie_headers = _headers(
            _get(fields, "http_http_cookie", "http_cookie")
        )
        for cookie_header in cookie_headers:
            for name, value in _parse_pairs(cookie_header, limit=MAX_COOKIE_PAIRS):
                kind = _name_kind(name, cookie=True)
                if kind is None and not value:
                    continue
                collector.add(
                    kind or "UNKNOWN_SECRET",
                    f"Cookie: {name[:64]}",
                    value or None,
                    source="http.cookie",
                    meta={"cookie_name": name[:128]},
                )

        set_cookies = _headers(
            _get(fields, "http_http_set_cookie", "http_set_cookie")
        )
        for set_cookie in set_cookies:
            first = set_cookie.split(";", 1)[0]
            name, _, value = first.partition("=")
            name, value = name.strip(), value.strip()
            kind = _name_kind(name, cookie=True)
            if name and (kind is not None or value):
                collector.add(
                    kind or "UNKNOWN_SECRET",
                    f"Set-Cookie: {name[:64]}",
                    value or None,
                    source="http.set_cookie",
                    meta={
                        "cookie_name": name[:128],
                        "attributes": _cookie_attributes(set_cookie),
                    },
                )

        uri = _text(_get(fields, "http_http_request_uri", "http_request_uri"))
        if uri:
            split = urlsplit(uri)
            if split.query:
                for name, value in parse_qsl(split.query, keep_blank_values=False)[:16]:
                    kind = _name_kind(name, cookie=False)
                    if kind is None:
                        continue
                    collector.add(
                        kind,
                        f"query: {name[:64]}",
                        value,
                        source="http.url_query",
                    )

        form_key = _text(
            _get(
                fields,
                "urlencoded_form_key",
                "urlencoded_form_urlencoded_form_key",
            )
        )
        form_value = _text(
            _get(
                fields,
                "urlencoded_form_value",
                "urlencoded_form_urlencoded_form_value",
            )
        )
        if form_key and form_value:
            lowered = form_key.lower()
            if lowered in PASSWORD_KEYS:
                collector.add(
                    "PASSWORD",
                    f"form: {form_key[:64]}",
                    form_value,
                    source="http.form",
                )
            elif lowered in EMAIL_KEYS:
                collector.add(
                    "PERSONAL_INFORMATION",
                    f"form: {form_key[:64]}",
                    form_value,
                    source="http.form",
                    meta={"kind": "email"},
                )
            elif lowered in USERNAME_KEYS:
                collector.add(
                    "PERSONAL_INFORMATION",
                    f"form: {form_key[:64]}",
                    form_value,
                    source="http.form",
                    meta={"kind": "username"},
                )

    if (packet.get("app_proto") or "").lower() == "ftp":
        command = _text(_get(fields, "ftp_ftp_request_command", "ftp_request_command"))
        argument = _text(_get(fields, "ftp_ftp_request_arg", "ftp_request_arg"))
        if command and argument:
            upper = command.strip().upper()
            if upper == "PASS":
                collector.add("PASSWORD", "FTP PASS", argument, source="ftp")
            elif upper == "USER":
                collector.add(
                    "PERSONAL_INFORMATION",
                    "FTP USER",
                    argument,
                    source="ftp",
                    meta={"kind": "username"},
                )

    return list(collector.items.values())
