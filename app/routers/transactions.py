"""Transactions: holders see and move their own money; admins and auditors see everything (read-only)."""

import uuid
from datetime import datetime
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, aliased, selectinload

from .. import ledger
from ..db import get_db
from ..deps import get_current_user, require_account_holder
from ..models import Account, Role, Transaction, TransactionType, User
from ..schemas import AccountRef, Page, TransactionOut, TransferIn, TransferOut, UserRef

router = APIRouter(prefix="/api/transactions", tags=["transactions"])

_LOAD = (
    selectinload(Transaction.account).selectinload(Account.owner),
    selectinload(Transaction.counterparty).selectinload(Account.owner),
    selectinload(Transaction.initiated_by),
)


def to_out(txn: Transaction, oversight: bool) -> TransactionOut:
    out = TransactionOut(
        id=txn.id,
        reference=txn.reference,
        type=txn.type,
        amount=txn.amount,
        currency=txn.currency,
        balance_after=txn.balance_after,
        description=txn.description,
        created_at=txn.created_at,
        transfer_id=txn.transfer_id,
        account=AccountRef.model_validate(txn.account),
        counterparty_account_number=txn.counterparty.account_number if txn.counterparty else None,
    )
    if oversight:
        out.owner = UserRef.model_validate(txn.account.owner)
        out.initiated_by = UserRef.model_validate(txn.initiated_by) if txn.initiated_by else None
        out.counterparty_owner = UserRef.model_validate(txn.counterparty.owner) if txn.counterparty else None
    return out


def is_oversight(user: User) -> bool:
    return user.role in (Role.ADMIN, Role.AUDITOR)


@router.get("", response_model=Page[TransactionOut])
def list_transactions(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    account_id: uuid.UUID | None = None,
    account_number: str | None = Query(default=None, max_length=14),
    owner: str | None = Query(default=None, max_length=254, description="Owner email, username or name contains"),
    tx_type: TransactionType | None = Query(default=None, alias="type"),
    reference: str | None = Query(default=None, max_length=16),
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    min_amount: Decimal | None = Query(default=None, ge=0),
    max_amount: Decimal | None = Query(default=None, ge=0),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
):
    """Account holders: only their own accounts. Admins and auditors: all transactions."""
    owner_user = aliased(User)
    q = select(Transaction).join(Account, Transaction.account_id == Account.id).join(
        owner_user, Account.owner_id == owner_user.id
    )
    oversight = is_oversight(user)
    if not oversight:
        q = q.where(Account.owner_id == user.id)

    if account_id:
        q = q.where(Transaction.account_id == account_id)
    if account_number:
        q = q.where(Account.account_number == account_number.replace(" ", ""))
    if owner and oversight:
        like = f"%{owner.lower()}%"
        q = q.where(or_(func.lower(owner_user.email).like(like), func.lower(owner_user.full_name).like(like),
                        owner_user.username.like(like)))
    if tx_type:
        q = q.where(Transaction.type == tx_type)
    if reference:
        q = q.where(Transaction.reference == reference.strip().upper())
    if date_from:
        q = q.where(Transaction.created_at >= date_from)
    if date_to:
        q = q.where(Transaction.created_at <= date_to)
    if min_amount is not None:
        q = q.where(Transaction.amount >= min_amount)
    if max_amount is not None:
        q = q.where(Transaction.amount <= max_amount)

    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = db.scalars(
        q.options(*_LOAD)
        .order_by(Transaction.created_at.desc(), Transaction.reference.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return Page(items=[to_out(t, oversight) for t in rows], total=total, page=page, page_size=page_size)


@router.get("/{transaction_id}", response_model=TransactionOut)
def get_transaction(transaction_id: uuid.UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    txn = db.get(Transaction, transaction_id, options=list(_LOAD))
    if txn is None or (not is_oversight(user) and txn.account.owner_id != user.id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Transaction not found")
    return to_out(txn, is_oversight(user))


@router.post("/transfer", response_model=TransferOut, status_code=status.HTTP_201_CREATED)
def make_transfer(
    body: TransferIn, request: Request, user: User = Depends(require_account_holder), db: Session = Depends(get_db)
):
    transfer_id, debit, credit = ledger.transfer(
        db, request, user, body.from_account_id, body.to_account_number, body.amount, body.description
    )
    debit = db.get(Transaction, debit.id, options=list(_LOAD))
    credit = db.get(Transaction, credit.id, options=list(_LOAD))
    own_credit = credit.account.owner_id == user.id
    return TransferOut(transfer_id=transfer_id, debit=to_out(debit, False),
                       credit=to_out(credit, False) if own_credit else None)
