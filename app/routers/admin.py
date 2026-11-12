"""Admin endpoints: user management, onboarding review, account controls, dashboard stats."""

import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session, selectinload

from .. import audit, ledger
from ..db import get_db
from ..deps import require_admin, require_oversight
from ..models import (
    Account, AccountStatus, AuditLog, RefreshToken, Role, Transaction, TransactionType, User, UserStatus,
)
from ..schemas import (
    AccountReviewIn,
    AdminAccountOut,
    AdminUserCreateIn,
    AdminUserUpdateIn,
    AuditLogOut,
    MoneyIn,
    Page,
    StatsOut,
    TransactionOut,
    UserOut,
)
from ..security import hash_password
from .auth import ensure_unique_identity
from .transactions import _LOAD, to_out

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------- Dashboard ----------------
@router.get("/stats", response_model=StatsOut)
def stats(_: User = Depends(require_oversight), db: Session = Depends(get_db)):
    users_by_role = {r.value: 0 for r in Role}
    for role, count in db.execute(select(User.role, func.count()).group_by(User.role)):
        users_by_role[role.value] = count

    accounts_by_status = {s.value: 0 for s in AccountStatus}
    for st, count in db.execute(select(Account.status, func.count()).group_by(Account.status)):
        accounts_by_status[st.value] = count

    balances = {
        currency: total or Decimal("0")
        for currency, total in db.execute(
            select(Account.currency, func.sum(Account.balance))
            .where(Account.status == AccountStatus.ACTIVE)
            .group_by(Account.currency)
        )
    }
    recent = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(8)).all()
    tx_total = db.scalar(select(func.count()).select_from(Transaction))
    tx_24h = db.scalar(select(func.count()).select_from(Transaction)
                       .where(Transaction.created_at >= _now() - timedelta(hours=24)))
    return StatsOut(
        users_by_role=users_by_role,
        accounts_by_status=accounts_by_status,
        pending_applications=accounts_by_status[AccountStatus.PENDING_APPROVAL.value],
        total_active_balance=balances,
        transactions_total=tx_total,
        transactions_last_24h=tx_24h,
        recent_activity=[AuditLogOut.model_validate(r) for r in recent],
    )


# ---------------- Users ----------------
@router.get("/users", response_model=Page[UserOut])
def list_users(
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
    search: str | None = Query(default=None, max_length=100),
    role: Role | None = None,
    user_status: UserStatus | None = Query(default=None, alias="status"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
):
    q = select(User)
    if search:
        like = f"%{search.lower()}%"
        q = q.where(or_(func.lower(User.email).like(like), func.lower(User.full_name).like(like),
                        User.username.like(like)))
    if role:
        q = q.where(User.role == role)
    if user_status:
        q = q.where(User.status == user_status)
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    items = db.scalars(q.order_by(User.created_at.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    return Page(items=[UserOut.model_validate(u) for u in items], total=total, page=page, page_size=page_size)


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    body: AdminUserCreateIn, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)
):
    ensure_unique_identity(db, body.email, body.username)
    user = User(
        email=body.email,
        username=body.username,
        full_name=body.full_name,
        phone=body.phone,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    db.flush()
    audit.record(db, "user.created", actor=admin, request=request, entity_type="user", entity_id=user.id,
                 details={"email": user.email, "role": user.role.value})
    db.commit()
    db.refresh(user)
    return user


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: uuid.UUID,
    body: AdminUserUpdateIn,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if user.id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot change your own role or status")

    changes: dict[str, dict[str, str]] = {}
    if body.role is not None and body.role != user.role:
        changes["role"] = {"from": user.role.value, "to": body.role.value}
        user.role = body.role
    if body.status is not None and body.status != user.status:
        changes["status"] = {"from": user.status.value, "to": body.status.value}
        user.status = body.status

    if not changes:
        return user

    if "status" in changes and user.status == UserStatus.SUSPENDED:
        # Force sign-out everywhere.
        db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=_now())
        )
    audit.record(db, "user.updated", actor=admin, request=request, entity_type="user", entity_id=user.id,
                 details={"email": user.email, **changes})
    db.commit()
    db.refresh(user)
    return user


# ---------------- Accounts / onboarding review ----------------
@router.get("/accounts", response_model=Page[AdminAccountOut])
def list_accounts(
    _: User = Depends(require_oversight),
    db: Session = Depends(get_db),
    account_status: AccountStatus | None = Query(default=None, alias="status"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
):
    q = select(Account)
    if account_status:
        q = q.where(Account.status == account_status)
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    # Pending queue is first-come first-served; other views show newest first.
    order = Account.created_at.asc() if account_status == AccountStatus.PENDING_APPROVAL else Account.created_at.desc()
    items = db.scalars(
        q.options(selectinload(Account.owner), selectinload(Account.reviewed_by))
        .order_by(order)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return Page(items=[AdminAccountOut.model_validate(a) for a in items], total=total, page=page, page_size=page_size)


def _get_account(db: Session, account_id: uuid.UUID) -> Account:
    account = db.get(Account, account_id, options=[selectinload(Account.owner)])
    if account is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Account not found")
    return account


@router.post("/accounts/{account_id}/review", response_model=AdminAccountOut)
def review_application(
    account_id: uuid.UUID,
    body: AccountReviewIn,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    account = _get_account(db, account_id)
    if account.status != AccountStatus.PENDING_APPROVAL:
        raise HTTPException(status.HTTP_409_CONFLICT, "This application has already been reviewed")

    account.status = AccountStatus.ACTIVE if body.decision == "approve" else AccountStatus.REJECTED
    account.reviewed_by_id = admin.id
    account.reviewed_at = _now()
    account.review_note = (body.note or "").strip() or None
    audit.record(
        db, f"account.{'approved' if body.decision == 'approve' else 'rejected'}", actor=admin, request=request,
        entity_type="account", entity_id=account.id,
        details={"account_number": account.account_number, "owner": account.owner.email, "note": account.review_note},
    )
    db.commit()
    db.refresh(account)
    return account


def _transition(
    db: Session, request: Request, admin: User, account_id: uuid.UUID,
    expected: AccountStatus, target: AccountStatus, action: str,
) -> Account:
    account = _get_account(db, account_id)
    if account.status != expected:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Account must be {expected.value} to do this")
    account.status = target
    audit.record(db, action, actor=admin, request=request, entity_type="account", entity_id=account.id,
                 details={"account_number": account.account_number, "owner": account.owner.email})
    db.commit()
    db.refresh(account)
    return account


@router.post("/accounts/{account_id}/freeze", response_model=AdminAccountOut)
def freeze_account(account_id: uuid.UUID, request: Request, admin: User = Depends(require_admin),
                   db: Session = Depends(get_db)):
    return _transition(db, request, admin, account_id, AccountStatus.ACTIVE, AccountStatus.FROZEN, "account.frozen")


@router.post("/accounts/{account_id}/unfreeze", response_model=AdminAccountOut)
def unfreeze_account(account_id: uuid.UUID, request: Request, admin: User = Depends(require_admin),
                     db: Session = Depends(get_db)):
    return _transition(db, request, admin, account_id, AccountStatus.FROZEN, AccountStatus.ACTIVE, "account.unfrozen")


# ---------------- Money movements (admin only) ----------------
@router.post("/accounts/{account_id}/deposit", response_model=TransactionOut, status_code=status.HTTP_201_CREATED)
def deposit(account_id: uuid.UUID, body: MoneyIn, request: Request, admin: User = Depends(require_admin),
            db: Session = Depends(get_db)):
    txn = ledger.deposit_or_withdraw(db, request, admin, account_id, TransactionType.DEPOSIT,
                                     body.amount, body.description)
    return to_out(db.get(Transaction, txn.id, options=list(_LOAD)), True)


@router.post("/accounts/{account_id}/withdraw", response_model=TransactionOut, status_code=status.HTTP_201_CREATED)
def withdraw(account_id: uuid.UUID, body: MoneyIn, request: Request, admin: User = Depends(require_admin),
             db: Session = Depends(get_db)):
    txn = ledger.deposit_or_withdraw(db, request, admin, account_id, TransactionType.WITHDRAWAL,
                                     body.amount, body.description)
    return to_out(db.get(Transaction, txn.id, options=list(_LOAD)), True)
