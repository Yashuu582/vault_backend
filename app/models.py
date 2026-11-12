import enum
import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Role(str, enum.Enum):
    ADMIN = "ADMIN"
    AUDITOR = "AUDITOR"
    ACCOUNT_HOLDER = "ACCOUNT_HOLDER"


class UserStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"


class AccountType(str, enum.Enum):
    CHECKING = "CHECKING"
    SAVINGS = "SAVINGS"
    BUSINESS = "BUSINESS"


class AccountStatus(str, enum.Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    ACTIVE = "ACTIVE"
    REJECTED = "REJECTED"
    FROZEN = "FROZEN"
    CLOSED = "CLOSED"


class TransactionType(str, enum.Enum):
    DEPOSIT = "DEPOSIT"
    WITHDRAWAL = "WITHDRAWAL"
    TRANSFER_IN = "TRANSFER_IN"
    TRANSFER_OUT = "TRANSFER_OUT"


DEBIT_TYPES = (TransactionType.WITHDRAWAL, TransactionType.TRANSFER_OUT)

TS = DateTime(timezone=True)


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    # Optional sign-in name (lowercase). Users can sign in with email or username.
    username: Mapped[str | None] = mapped_column(String(50), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(100))
    full_name: Mapped[str] = mapped_column(String(120))
    phone: Mapped[str | None] = mapped_column(String(32))
    role: Mapped[Role] = mapped_column(Enum(Role, name="user_role"), default=Role.ACCOUNT_HOLDER)
    status: Mapped[UserStatus] = mapped_column(Enum(UserStatus, name="user_status"), default=UserStatus.ACTIVE)
    last_login_at: Mapped[datetime | None] = mapped_column(TS)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), onupdate=func.now())

    accounts: Mapped[list["Account"]] = relationship(back_populates="owner", foreign_keys="Account.owner_id")


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_number: Mapped[str] = mapped_column(String(12), unique=True)
    nickname: Mapped[str | None] = mapped_column(String(60))
    type: Mapped[AccountType] = mapped_column(Enum(AccountType, name="account_type"))
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    balance: Mapped[Decimal] = mapped_column(Numeric(18, 2), default=Decimal("0.00"))
    status: Mapped[AccountStatus] = mapped_column(
        Enum(AccountStatus, name="account_status"), default=AccountStatus.PENDING_APPROVAL, index=True
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    reviewed_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    reviewed_at: Mapped[datetime | None] = mapped_column(TS)
    review_note: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), onupdate=func.now())

    owner: Mapped[User] = relationship(back_populates="accounts", foreign_keys=[owner_id])
    reviewed_by: Mapped[User | None] = relationship(foreign_keys=[reviewed_by_id])


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    family_id: Mapped[uuid.UUID] = mapped_column(Uuid, index=True)
    expires_at: Mapped[datetime] = mapped_column(TS)
    revoked_at: Mapped[datetime | None] = mapped_column(TS)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    user_agent: Mapped[str | None] = mapped_column(String(255))
    ip: Mapped[str | None] = mapped_column(String(64))

    user: Mapped[User] = relationship()


class Transaction(Base):
    """One ledger entry = one movement on one account. Append-only (DB trigger blocks UPDATE/DELETE).

    A transfer creates two entries (TRANSFER_OUT on the source, TRANSFER_IN on the destination)
    that share the same `transfer_id`.
    """

    __tablename__ = "transactions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    reference: Mapped[str] = mapped_column(String(16), unique=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("accounts.id"), index=True)
    type: Mapped[TransactionType] = mapped_column(Enum(TransactionType, name="transaction_type"), index=True)
    amount: Mapped[Decimal] = mapped_column(Numeric(18, 2))
    currency: Mapped[str] = mapped_column(String(3))
    balance_after: Mapped[Decimal] = mapped_column(Numeric(18, 2))
    counterparty_account_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("accounts.id"))
    transfer_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)
    description: Mapped[str | None] = mapped_column(String(200))
    initiated_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), index=True)

    account: Mapped[Account] = relationship(foreign_keys=[account_id])
    counterparty: Mapped[Account | None] = relationship(foreign_keys=[counterparty_account_id])
    initiated_by: Mapped[User | None] = relationship(foreign_keys=[initiated_by_id])


class PasswordResetToken(Base):
    """Single-use, short-lived token for the forgot-password flow. Only a SHA-256 hash is stored."""

    __tablename__ = "password_reset_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(TS)
    used_at: Mapped[datetime | None] = mapped_column(TS)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    ip: Mapped[str | None] = mapped_column(String(64))

    user: Mapped[User] = relationship()


class AuditLog(Base):
    """Append-only. UPDATE/DELETE/TRUNCATE are blocked by a DB trigger (see migration)."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), index=True)
    actor_email: Mapped[str | None] = mapped_column(String(254))
    action: Mapped[str] = mapped_column(String(64), index=True)
    entity_type: Mapped[str | None] = mapped_column(String(32))
    entity_id: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict | None] = mapped_column(JSON().with_variant(JSONB, "postgresql"))
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), index=True)
