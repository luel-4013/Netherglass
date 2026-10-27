"""Role-based access control.

Permission names follow the specification (section 20) plus three operational
permissions for emergency-stop handling and user management. Design rule: a user
who can view packets must not automatically be able to reveal secrets; a user
who can view sensitive evidence must not automatically be able to use it in an
active test.
"""

from __future__ import annotations

from enum import Enum


class Permission(str, Enum):
    VIEW_NETWORK_METADATA = "VIEW_NETWORK_METADATA"
    VIEW_FINDINGS = "VIEW_FINDINGS"
    VIEW_SENSITIVE_METADATA = "VIEW_SENSITIVE_METADATA"
    VIEW_SENSITIVE_VALUES = "VIEW_SENSITIVE_VALUES"
    EXPORT_EVIDENCE = "EXPORT_EVIDENCE"
    EXPORT_SENSITIVE_EVIDENCE = "EXPORT_SENSITIVE_EVIDENCE"
    DELETE_EVIDENCE = "DELETE_EVIDENCE"
    MANAGE_CAPTURE_PROFILES = "MANAGE_CAPTURE_PROFILES"
    ENABLE_FULL_CAPTURE = "ENABLE_FULL_CAPTURE"
    CREATE_CONTROLLED_TEST = "CREATE_CONTROLLED_TEST"
    EXECUTE_CONTROLLED_TEST = "EXECUTE_CONTROLLED_TEST"
    TRIGGER_EMERGENCY_STOP = "TRIGGER_EMERGENCY_STOP"
    RECOVER_EMERGENCY_STOP = "RECOVER_EMERGENCY_STOP"
    CONTROL_CAPTURE = "CONTROL_CAPTURE"
    VIEW_AUDIT_LOG = "VIEW_AUDIT_LOG"
    MANAGE_USERS = "MANAGE_USERS"


_ANALYST: frozenset[Permission] = frozenset(
    {
        Permission.VIEW_NETWORK_METADATA,
        Permission.VIEW_FINDINGS,
        Permission.VIEW_SENSITIVE_METADATA,
        Permission.EXPORT_EVIDENCE,
        Permission.CREATE_CONTROLLED_TEST,
        Permission.TRIGGER_EMERGENCY_STOP,
        Permission.CONTROL_CAPTURE,
    }
)

_AUDITOR: frozenset[Permission] = frozenset(
    {
        Permission.VIEW_NETWORK_METADATA,
        Permission.VIEW_FINDINGS,
        Permission.VIEW_AUDIT_LOG,
    }
)

_ADMIN: frozenset[Permission] = frozenset(Permission)

ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "admin": _ADMIN,
    "analyst": _ANALYST,
    "auditor": _AUDITOR,
}


def role_exists(role: str) -> bool:
    return role in ROLE_PERMISSIONS


def has_permission(role: str, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, frozenset())


def permissions_for(role: str) -> list[str]:
    return sorted(p.value for p in ROLE_PERMISSIONS.get(role, frozenset()))
