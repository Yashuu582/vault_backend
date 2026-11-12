import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..db import get_db
from ..deps import ACCESS_COOKIE, REFRESH_COOKIE, get_current_user
from ..mailer import send_password_reset
from ..models import PasswordResetToken, RefreshToken, Role, User, UserStatus
from ..rate_limit import client_ip, enforce
from ..schemas import ForgotPasswordIn, LoginIn, MessageOut, RegisterIn, ResetPasswordIn, UserOut
from ..security import (
    DUMMY_PASSWORD_HASH,
    create_access_token,
    hash_password,
    hash_token,
    new_refresh_token,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])
settings = get_settings()
REFRESH_PATH = "/api/auth"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _set_session_cookies(response: Response, access: str, refresh: str) -> None:
    common = {"httponly": True, "secure": settings.cookie_secure, "samesite": settings.cookie_samesite}
    response.set_cookie(ACCESS_COOKIE, access, max_age=settings.access_token_ttl_minutes * 60, path="/", **common)
    response.set_cookie(
        REFRESH_COOKIE, refresh, max_age=settings.refresh_token_ttl_days * 86400, path=REFRESH_PATH, **common
    )


def _clear_session_cookies(response: Response) -> None:
    response.delete_cookie(ACCESS_COOKIE, path="/")
    response.delete_cookie(REFRESH_COOKIE, path=REFRESH_PATH)


def _issue_session(
    db: Session, response: Response, request: Request, user: User, family_id: uuid.UUID | None = None
) -> None:
    raw, token_hash = new_refresh_token()
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=token_hash,
            family_id=family_id or uuid.uuid4(),
            expires_at=_utcnow() + timedelta(days=settings.refresh_token_ttl_days),
            user_agent=request.headers.get("user-agent", "")[:255] or None,
            ip=client_ip(request),
        )
    )
    _set_session_cookies(response, create_access_token(user), raw)


def find_user(db: Session, identifier: str) -> User | None:
    """Look a user up by email (contains '@') or username. `identifier` is already lowercased."""
    column = User.email if "@" in identifier else User.username
    return db.scalar(select(User).where(column == identifier))


def ensure_unique_identity(db: Session, email: str, username: str | None) -> None:
    if db.scalar(select(User.id).where(User.email == email)):
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists")
    if username and db.scalar(select(User.id).where(User.username == username)):
        raise HTTPException(status.HTTP_409_CONFLICT, "This username is already taken")


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(body: RegisterIn, request: Request, response: Response, db: Session = Depends(get_db)):
    """Sign up: self-service onboarding for account holders. Staff accounts are created by admins."""
    enforce(f"register:ip:{client_ip(request)}", settings.register_rate_limit, settings.register_rate_window)
    ensure_unique_identity(db, body.email, body.username)

    user = User(
        email=body.email,
        username=body.username,
        full_name=body.full_name,
        phone=body.phone,
        password_hash=hash_password(body.password),
        role=Role.ACCOUNT_HOLDER,
        last_login_at=_utcnow(),
    )
    db.add(user)
    db.flush()
    audit.record(db, "auth.register", actor=user, request=request, entity_type="user", entity_id=user.id)
    _issue_session(db, response, request, user)
    db.commit()
    return user


@router.post("/login", response_model=UserOut)
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = client_ip(request)
    enforce(f"login:ip:{ip}", settings.login_rate_limit * 4, settings.login_rate_window)
    enforce(f"login:id:{body.identifier}", settings.login_rate_limit, settings.login_rate_window)

    user = find_user(db, body.identifier)
    password_ok = verify_password(body.password, user.password_hash if user else DUMMY_PASSWORD_HASH)

    if user is None or not password_ok:
        audit.record(
            db, "auth.login_failed", actor=user, actor_email=body.identifier[:254], request=request,
            entity_type="user", entity_id=user.id if user else None,
        )
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email/username or password")

    if user.status != UserStatus.ACTIVE:
        audit.record(db, "auth.login_blocked", actor=user, request=request, entity_type="user", entity_id=user.id,
                     details={"reason": user.status.value})
        db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This account is suspended. Contact support.")

    user.last_login_at = _utcnow()
    audit.record(db, "auth.login", actor=user, request=request, entity_type="user", entity_id=user.id)
    _issue_session(db, response, request, user)
    db.commit()
    return user


@router.post("/refresh", response_model=UserOut)
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    raw = request.cookies.get(REFRESH_COOKIE)
    if not raw:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")

    token = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_token(raw)))
    if token is None:
        _clear_session_cookies(response)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired")

    now = _utcnow()
    if token.revoked_at is not None:
        # A rotated token was replayed: assume theft and kill the whole session family.
        db.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == token.family_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        audit.record(db, "auth.refresh_reuse_detected", actor=token.user, request=request,
                     entity_type="user", entity_id=token.user_id)
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired")

    user = token.user
    if _as_utc(token.expires_at) <= now or user.status != UserStatus.ACTIVE:
        token.revoked_at = now
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired")

    token.revoked_at = now
    _issue_session(db, response, request, user, family_id=token.family_id)
    db.commit()
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    raw = request.cookies.get(REFRESH_COOKIE)
    if raw:
        token = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_token(raw)))
        if token is not None and token.revoked_at is None:
            token.revoked_at = _utcnow()
            audit.record(db, "auth.logout", actor=token.user, request=request,
                         entity_type="user", entity_id=token.user_id)
            db.commit()
    _clear_session_cookies(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


FORGOT_MESSAGE = "If an account matches, we've sent a link to reset the password. Check your email."


@router.post("/forgot-password", response_model=MessageOut, status_code=status.HTTP_202_ACCEPTED)
def forgot_password(
    body: ForgotPasswordIn, request: Request, background: BackgroundTasks, db: Session = Depends(get_db)
):
    """Start a password reset. Always returns the same message, so it never reveals whether an account exists."""
    enforce(f"forgot:ip:{client_ip(request)}", settings.forgot_password_rate_limit * 3,
            settings.forgot_password_rate_window)
    enforce(f"forgot:id:{body.identifier}", settings.forgot_password_rate_limit, settings.forgot_password_rate_window)

    user = find_user(db, body.identifier)
    if user is not None and user.status == UserStatus.ACTIVE:
        now = _utcnow()
        # Only the newest link works: invalidate earlier unused ones.
        db.execute(
            update(PasswordResetToken)
            .where(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None))
            .values(used_at=now)
        )
        raw, token_hash = new_refresh_token()
        db.add(PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=now + timedelta(minutes=settings.password_reset_ttl_minutes),
            ip=client_ip(request),
        ))
        audit.record(db, "auth.password_reset_requested", actor=user, request=request,
                     entity_type="user", entity_id=user.id)
        db.commit()
        link = f"{settings.frontend_url.rstrip('/')}/reset-password?token={raw}"
        background.add_task(send_password_reset, user.email, user.full_name, link,
                            settings.password_reset_ttl_minutes)
    return MessageOut(message=FORGOT_MESSAGE)


@router.post("/reset-password", response_model=MessageOut)
def reset_password(body: ResetPasswordIn, request: Request, db: Session = Depends(get_db)):
    enforce(f"reset:ip:{client_ip(request)}", 10, 3600)

    token = db.scalar(select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_token(body.token)))
    now = _utcnow()
    if (
        token is None
        or token.used_at is not None
        or _as_utc(token.expires_at) <= now
        or token.user.status != UserStatus.ACTIVE
    ):
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "This reset link is invalid or has expired. Please request a new one.")

    user = token.user
    user.password_hash = hash_password(body.new_password)
    token.used_at = now
    # Sign the user out everywhere: whoever had the old password loses access.
    db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    audit.record(db, "auth.password_reset", actor=user, request=request, entity_type="user", entity_id=user.id)
    db.commit()
    return MessageOut(message="Your password has been reset. You can now sign in with your new password.")


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user
