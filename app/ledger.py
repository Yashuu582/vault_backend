"""Money movements. Every change to an account balance goes through here.

Rules:
- Accounts must be ACTIVE (frozen, pending, rejected or closed accounts cannot move money).
- Balances never go below zero.
- Account rows are locked (SELECT ... FOR UPDATE, in a fixed order) for the duration of the
  transaction, so concurrent requests cannot both spend the same balance.
- The ledger entry, the balance update and the audit record commit together or not at all.
"""

import secrets
import string
import uuid
from decimal import Decimal

from fastapi import HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .models import DEBIT_TYPES, Account, AccountStatus, Transaction, TransactionType, User

_REF_ALPHABET = string.ascii_uppercase + string.digits


def _new_reference(db: Session) -> str:
    for _ in range(10):
        ref = "TX" + "".join(secrets.choice(_REF_ALPHABET) for _ in range(10))
        if not db.scalar(select(Transaction.id).where(Transaction.reference == ref)):
            return ref
    raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Could not allocate a reference, retry")


def lock_accounts(db: Session, account_ids: list[uuid.UUID]) -> dict[uuid.UUID, Account]:
    """Lock the given accounts (sorted to avoid deadlocks) and return fresh rows."""
    rows = db.scalars(
        select(Account)
        .where(Account.id.in_(account_ids))
        .order_by(Account.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).all()
    return {a.id: a for a in rows}


def _require_active(account: Account, label: str = "Account") -> None:
    if account.status != AccountStatus.ACTIVE:
        status_text = account.status.value.replace("_", " ").lower()
        raise HTTPException(status.HTTP_409_CONFLICT, f"{label} is {status_text} and cannot move money")


def _post(
    db: Session,
    account: Account,
    tx_type: TransactionType,
    amount: Decimal,
    actor: User,
    description: str | None,
    counterparty: Account | None = None,
    transfer_id: uuid.UUID | None = None,
) -> Transaction:
    if tx_type in DEBIT_TYPES:
        if account.balance < amount:
            raise HTTPException(status.HTTP_409_CONFLICT, "Insufficient funds")
        account.balance = account.balance - amount
    else:
        account.balance = account.balance + amount

    txn = Transaction(
        reference=_new_reference(db),
        account_id=account.id,
        type=tx_type,
        amount=amount,
        currency=account.currency,
        balance_after=account.balance,
        counterparty_account_id=counterparty.id if counterparty else None,
        transfer_id=transfer_id,
        description=description,
        initiated_by_id=actor.id,
    )
    db.add(txn)
    return txn


def deposit_or_withdraw(
    db: Session, request: Request, admin: User, account_id: uuid.UUID,
    tx_type: TransactionType, amount: Decimal, description: str | None,
) -> Transaction:
    account = lock_accounts(db, [account_id]).get(account_id)
    if account is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Account not found")
    _require_active(account)
    txn = _post(db, account, tx_type, amount, admin, description)
    db.flush()
    audit.record(
        db, f"transaction.{tx_type.value.lower()}", actor=admin, request=request,
        entity_type="transaction", entity_id=txn.id,
        details={"reference": txn.reference, "account_number": account.account_number,
                 "amount": str(amount), "currency": account.currency},
    )
    db.commit()
    return txn


def transfer(
    db: Session, request: Request, holder: User, from_account_id: uuid.UUID,
    to_account_number: str, amount: Decimal, description: str | None,
) -> tuple[uuid.UUID, Transaction, Transaction]:
    to_id = db.scalar(select(Account.id).where(Account.account_number == to_account_number))
    if to_id is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Destination account not found")
    if to_id == from_account_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Choose a different destination account")

    locked = lock_accounts(db, [from_account_id, to_id])
    source, dest = locked.get(from_account_id), locked.get(to_id)
    # 404 (not 403) so other people's account ids are not confirmed.
    if source is None or source.owner_id != holder.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Source account not found")
    _require_active(source, "Your account")
    if dest is None or dest.status != AccountStatus.ACTIVE:
        raise HTTPException(status.HTTP_409_CONFLICT, "Destination account cannot receive money")
    if dest.currency != source.currency:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f"Currency mismatch: {source.currency} cannot be sent to a {dest.currency} account")

    transfer_id = uuid.uuid4()
    debit = _post(db, source, TransactionType.TRANSFER_OUT, amount, holder, description, dest, transfer_id)
    credit = _post(db, dest, TransactionType.TRANSFER_IN, amount, holder, description, source, transfer_id)
    db.flush()
    audit.record(
        db, "transaction.transfer", actor=holder, request=request,
        entity_type="transaction", entity_id=transfer_id,
        details={"from": source.account_number, "to": dest.account_number, "amount": str(amount),
                 "currency": source.currency, "debit_ref": debit.reference, "credit_ref": credit.reference},
    )
    db.commit()
    return transfer_id, debit, credit
