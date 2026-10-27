"""Authentication: argon2id passwords, server-side sessions, login rate limits.

Session model:
- The cookie carries an opaque random id (never user data).
- The database stores only the SHA-256 of the session id.
- Each session carries its own CSRF token used for state-changing requests.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .audit import utcnow_iso
from .rbac import role_exists

SESSION_COOKIE = "ng_session"

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def create_user(conn, username: str, password: str, role: str = "analyst") -> dict:
    if not role_exists(role):
        raise ValueError(f"unknown role: {role}")
    cursor = conn.execute(
        "INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
        (username, hash_password(password), role, utcnow_iso()),
    )
    return {"id": cursor.lastrowid, "username": username, "role": role}


def authenticate(conn, username: str, password: str) -> dict | None:
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None or row["disabled"]:
        return None
    if not verify_password(row["password_hash"], password):
        return None
    return {"id": row["id"], "username": row["username"], "role": row["role"]}


def _session_hash(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def create_session(conn, user_id: int, ttl_hours: int, ip: str | None, user_agent: str | None) -> tuple[str, str]:
    session_id = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=ttl_hours)
    conn.execute(
        "INSERT INTO sessions(id_hash, user_id, csrf_token, created_at, expires_at, "
        "last_seen, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            _session_hash(session_id),
            user_id,
            csrf_token,
            now.isoformat(timespec="seconds"),
            expires.isoformat(timespec="seconds"),
            now.isoformat(timespec="seconds"),
            ip,
            user_agent,
        ),
    )
    return session_id, csrf_token


def get_session(conn, session_id: str) -> dict | None:
    row = conn.execute(
        "SELECT s.csrf_token, s.expires_at, u.username, u.role, u.disabled "
        "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ?",
        (_session_hash(session_id),),
    ).fetchone()
    if row is None or row["disabled"]:
        return None
    if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
        return None
    return {
        "username": row["username"],
        "role": row["role"],
        "csrf_token": row["csrf_token"],
        "expires_at": row["expires_at"],
    }


def revoke_session(conn, session_id: str) -> None:
    conn.execute("DELETE FROM sessions WHERE id_hash = ?", (_session_hash(session_id),))


class LoginLimiter:
    def __init__(self, max_failures: int = 5, window_seconds: int = 300) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self._failures: dict[str, list[float]] = {}

    def _prune(self, key: str, now: float) -> list[float]:
        stamps = [t for t in self._failures.get(key, []) if now - t < self.window_seconds]
        if stamps:
            self._failures[key] = stamps
        else:
            self._failures.pop(key, None)
        return stamps

    def is_locked(self, key: str) -> bool:
        return len(self._prune(key, time.monotonic())) >= self.max_failures

    def record_failure(self, key: str) -> None:
        now = time.monotonic()
        stamps = self._prune(key, now)
        stamps.append(now)
        self._failures[key] = stamps

    def reset(self, key: str) -> None:
        self._failures.pop(key, None)
