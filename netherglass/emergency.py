"""Emergency Security Stop - a first-class containment control.

Contract (spec section 26):
- One deliberate action stops capture, processing, active tests, and exports.
- Evidence already collected is preserved; sensitive evidence is locked.
- The event is audited; secrets never appear in the audit record.
- The system stays in the stopped state until an authorized operator performs
  an explicit recovery with a reason. Nothing auto-restarts.
"""

from __future__ import annotations

import threading

from .security.audit import append_event
from .store.db import Database

EMERGENCY_KEY = "emergency_stopped"


class EmergencyStop:
    def __init__(self, db: Database) -> None:
        self.db = db
        self.capture_halt = threading.Event()
        with db.connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO system_state(key, value) VALUES (?, '0')",
                (EMERGENCY_KEY,),
            )

    def is_stopped(self) -> bool:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT value FROM system_state WHERE key = ?", (EMERGENCY_KEY,)
            ).fetchone()
        return bool(row and row["value"] == "1")

    def status(self) -> dict:
        stopped = self.is_stopped()
        return {
            "emergency_stopped": stopped,
            "capture": "STOPPED" if stopped else "READY",
            "processing": "STOPPED" if stopped else "IDLE",
            "active_tests": "ABORTED" if stopped else "NONE",
            "exports": "STOPPED" if stopped else "READY",
            "sensitive_evidence": "LOCKED" if stopped else "UNLOCKED",
            "recovery_required": stopped,
        }

    def trigger(self, actor: str, reason: str | None = None) -> dict:
        with self.db.connect() as conn:
            conn.execute(
                "UPDATE system_state SET value = '1' WHERE key = ?", (EMERGENCY_KEY,)
            )
            append_event(
                conn,
                actor=actor,
                action="EMERGENCY_SECURITY_STOP",
                target="system",
                details={
                    "reason": (reason or "Emergency security stop").strip() or "Emergency security stop",
                    "capture": "STOPPED",
                    "processing": "STOPPED",
                    "active_tests": "ABORTED",
                    "exports": "STOPPED",
                    "sensitive_evidence": "LOCKED",
                },
            )
        self.capture_halt.set()
        return self.status()

    def recover(self, actor: str, reason: str) -> dict:
        if not reason or not reason.strip():
            raise ValueError("recovery reason is required")
        with self.db.connect() as conn:
            conn.execute(
                "UPDATE system_state SET value = '0' WHERE key = ?", (EMERGENCY_KEY,)
            )
            append_event(
                conn,
                actor=actor,
                action="EMERGENCY_RECOVERY",
                target="system",
                details={"reason": reason.strip()},
            )
        self.capture_halt.clear()
        return self.status()

    def capture_allowed(self) -> bool:
        return not self.is_stopped()
