"""Role-based access control (RBAC) helpers."""

from __future__ import annotations

from enum import Enum
from typing import Annotated

from fastapi import Depends, HTTPException, status

from agentguard_console.auth.middleware import CurrentUser, get_current_user


class Permission(str, Enum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


# Role hierarchy: admin > operator > viewer
_ROLE_PERMISSIONS: dict[str, set[Permission]] = {
    "admin": {Permission.READ, Permission.WRITE, Permission.ADMIN},
    "operator": {Permission.READ, Permission.WRITE},
    "viewer": {Permission.READ},
}


def _check_permission(user: CurrentUser, required: Permission) -> None:
    allowed = _ROLE_PERMISSIONS.get(user.role, set())
    if required not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{user.role}' lacks '{required.value}' permission",
        )


def require_role(permission: Permission):
    """FastAPI dependency that enforces a minimum permission level."""

    async def _guard(
        user: Annotated[CurrentUser, Depends(get_current_user)],
    ) -> CurrentUser:
        _check_permission(user, permission)
        return user

    return _guard
