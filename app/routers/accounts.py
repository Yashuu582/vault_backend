"""Account-holder endpoints: view own accounts and apply for new ones (onboarding)."""

import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import require_account_holder
from ..models import Account, AccountStatus, User
from ..schemas import AccountCreateIn, AccountOut

router = APIRouter(prefix="/api/accounts", tags=["accounts"])

MAX_PENDING_APPLICATIONS = 3


def _generate_account_number(db: Session) -> str:
    for _ in range(10):
        number = "".join(str(secrets.randbelow(10)) for _ in range(12))
        if number[0] != "0" and not db.scalar(select(Account.id).where(Account.account_number == number)):
            return number
    raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Could not allocate an account number, retry")


@router.get("", response_model=list[AccountOut])
def list_my_accounts(user: User = Depends(require_account_holder), db: Session = Depends(get_db)):
    return db.scalars(select(Account).where(Account.owner_id == user.id).order_by(Account.created_at.desc())).all()


@router.post("", response_model=AccountOut, status_code=status.HTTP_201_CREATED)
def apply_for_account(
    body: AccountCreateIn,
    request: Request,
    user: User = Depends(require_account_holder),
    db: Session = Depends(get_db),
):
    pending = db.scalar(
        select(func.count())
        .select_from(Account)
        .where(Account.owner_id == user.id, Account.status == AccountStatus.PENDING_APPROVAL)
    )
    if pending >= MAX_PENDING_APPLICATIONS:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"You already have {pending} applications awaiting review. Please wait for a decision.",
        )

    account = Account(
        account_number=_generate_account_number(db),
        nickname=(body.nickname or "").strip() or None,
        type=body.type,
        currency=body.currency,
        owner_id=user.id,
        status=AccountStatus.PENDING_APPROVAL,
    )
    db.add(account)
    db.flush()
    audit.record(
        db, "account.applied", actor=user, request=request, entity_type="account", entity_id=account.id,
        details={"type": body.type.value, "currency": body.currency},
    )
    db.commit()
    db.refresh(account)
    return account


@router.get("/{account_id}", response_model=AccountOut)
def get_my_account(account_id: uuid.UUID, user: User = Depends(require_account_holder), db: Session = Depends(get_db)):
    account = db.get(Account, account_id)
    # 404 rather than 403 so account ids belonging to others are not confirmed.
    if account is None or account.owner_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Account not found")
    return account
