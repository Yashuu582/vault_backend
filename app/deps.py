import uuid

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .db import get_db
from .models import Role, User, UserStatus
from .security import decode_access_token

ACCESS_COOKIE = "bv_access"
REFRESH_COOKIE = "bv_refresh"


def _unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get(ACCESS_COOKIE)
    if not token:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth[7:]
    if not token:
        raise _unauthorized()

    payload = decode_access_token(token)
    if payload is None:
        raise _unauthorized("Session expired or invalid")

    try:
        user_id = uuid.UUID(payload["sub"])
    except (ValueError, KeyError):
        raise _unauthorized("Session expired or invalid")

    # Always re-read the user so suspensions and role changes apply immediately.
    user = db.get(User, user_id)
    if user is None or user.status != UserStatus.ACTIVE:
        raise _unauthorized("Session expired or invalid")
    return user


def require_roles(*roles: Role):
    """Dependency factory enforcing role-based access control."""

    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action",
            )
        return user

    return checker


require_admin = require_roles(Role.ADMIN)
require_oversight = require_roles(Role.ADMIN, Role.AUDITOR)
require_account_holder = require_roles(Role.ACCOUNT_HOLDER)
