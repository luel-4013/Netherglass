from pathlib import Path

from netherglass.security.auth import (
    LoginLimiter,
    authenticate,
    create_session,
    create_user,
    get_session,
    revoke_session,
)
from netherglass.security.rbac import Permission, has_permission, permissions_for
from netherglass.store.db import Database


def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "auth.db")
    db.migrate()
    return db


def test_password_hash_roundtrip(tmp_path: Path) -> None:
    db = _db(tmp_path)
    with db.connect() as conn:
        create_user(conn, "alice", "correct horse battery staple", "analyst")
        user = authenticate(conn, "alice", "correct horse battery staple")
        assert user is not None
        assert user["role"] == "analyst"
        assert authenticate(conn, "alice", "wrong") is None


def test_unknown_role_rejected(tmp_path: Path) -> None:
    db = _db(tmp_path)
    try:
        with db.connect() as conn:
            create_user(conn, "mallory", "password12345", "superuser")
        raised = False
    except ValueError:
        raised = True
    assert raised


def test_disabled_user_rejected(tmp_path: Path) -> None:
    db = _db(tmp_path)
    with db.connect() as conn:
        create_user(conn, "bob", "pw123456", "analyst")
        conn.execute("UPDATE users SET disabled = 1 WHERE username = 'bob'")
        assert authenticate(conn, "bob", "pw123456") is None


def test_session_lifecycle(tmp_path: Path) -> None:
    db = _db(tmp_path)
    with db.connect() as conn:
        user = create_user(conn, "carol", "pw123456", "auditor")
        sid, csrf = create_session(
            conn, user["id"], ttl_hours=1, ip="127.0.0.1", user_agent="test"
        )
        session = get_session(conn, sid)
        assert session is not None
        assert session["username"] == "carol"
        assert session["csrf_token"] == csrf
        revoke_session(conn, sid)
        assert get_session(conn, sid) is None


def test_expired_session_rejected(tmp_path: Path) -> None:
    db = _db(tmp_path)
    with db.connect() as conn:
        user = create_user(conn, "dave", "pw123456", "analyst")
        sid, _ = create_session(conn, user["id"], ttl_hours=-1, ip=None, user_agent=None)
        assert get_session(conn, sid) is None


def test_role_permission_matrix() -> None:
    assert has_permission("analyst", Permission.VIEW_NETWORK_METADATA)
    assert has_permission("analyst", Permission.TRIGGER_EMERGENCY_STOP)
    assert has_permission("analyst", Permission.CONTROL_CAPTURE)
    assert not has_permission("analyst", Permission.RECOVER_EMERGENCY_STOP)
    assert not has_permission("analyst", Permission.VIEW_SENSITIVE_VALUES)
    assert not has_permission("analyst", Permission.EXPORT_SENSITIVE_EVIDENCE)
    assert has_permission("admin", Permission.RECOVER_EMERGENCY_STOP)
    assert has_permission("auditor", Permission.VIEW_AUDIT_LOG)
    assert not has_permission("auditor", Permission.CONTROL_CAPTURE)
    assert not has_permission("auditor", Permission.EXPORT_SENSITIVE_EVIDENCE)
    assert "VIEW_AUDIT_LOG" in permissions_for("auditor")


def test_login_limiter_locks_after_failures() -> None:
    limiter = LoginLimiter(max_failures=3, window_seconds=60)
    key = "127.0.0.1|eve"
    assert limiter.is_locked(key) is False
    limiter.record_failure(key)
    limiter.record_failure(key)
    limiter.record_failure(key)
    assert limiter.is_locked(key) is True
    limiter.reset(key)
    assert limiter.is_locked(key) is False
