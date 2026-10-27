"""Logging with a mandatory secret-redaction filter.

Spec rule: sensitive values must never reach debug logs, application logs,
crash output, telemetry or unauthenticated API responses. Every handler added
here carries the filter, so the guarantee holds even for third-party loggers
that propagate to the root logger.
"""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path

REDACTION = "[REDACTED]"

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey)\b[\"']?\s*[:=]\s*"
            r"(\"[^\"]*\"|'[^']*'|[^\s,;'\"&]+)"
        ),
        r"\1=" + REDACTION,
    ),
    (
        re.compile(r"(?i)\bAuthorization\s*:\s*(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+"),
        r"Authorization: \1 " + REDACTION,
    ),
    (re.compile(r"(?i)\b(Set-)?Cookie\s*:\s*[^\r\n]+"), "Cookie: " + REDACTION),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        REDACTION,
    ),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTION),
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
        ),
        REDACTION,
    ),
]


def redact(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            record.msg = redact(str(record.msg))
            record.args = ()
            return True
        record.msg = redact(message)
        record.args = ()
        return True


def setup_logging(log_dir: Path | None = None, level: int = logging.INFO) -> None:
    formatter = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s %(message)s")
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_dir / "netherglass.log"))
    root = logging.getLogger()
    root.setLevel(level)
    for handler in handlers:
        handler.setFormatter(formatter)
        handler.addFilter(RedactingFilter())
        root.addHandler(handler)
