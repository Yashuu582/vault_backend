import re
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from .models import AccountStatus, AccountType, Role, TransactionType, UserStatus

T = TypeVar("T")

SUPPORTED_CURRENCIES = ("USD", "EUR", "GBP", "INR")


def _validate_password_strength(value: str) -> str:
    if len(value.encode("utf-8")) > 72:
        raise ValueError("Password must be at most 72 bytes")
    checks = [
        (r"[a-z]", "a lowercase letter"),
        (r"[A-Z]", "an uppercase letter"),
        (r"\d", "a digit"),
        (r"[^A-Za-z0-9]", "a symbol"),
    ]
    missing = [label for pattern, label in checks if not re.search(pattern, value)]
    if missing:
        raise ValueError("Password must contain " + ", ".join(missing))
    return value


USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,49}$")


def normalize_username(value: str | None) -> str | None:
    """Lowercase + validate an optional username. Empty means 'no username'."""
    if value is None or not value.strip():
        return None
    value = value.strip().lower()
    if not USERNAME_RE.match(value):
        raise ValueError(
            "Username must be 3-50 characters: letters, digits, '.', '_' or '-', starting with a letter or digit"
        )
    return value


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---------- Auth ----------
class RegisterIn(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    username: str | None = Field(default=None, max_length=50)
    phone: str | None = Field(default=None, pattern=r"^\+?[0-9 ()-]{7,20}$")
    password: str = Field(min_length=12, max_length=72)

    @field_validator("password")
    @classmethod
    def strong_password(cls, v: str) -> str:
        return _validate_password_strength(v)

    @field_validator("username")
    @classmethod
    def check_username(cls, v: str | None) -> str | None:
        return normalize_username(v)

    @field_validator("phone", mode="before")
    @classmethod
    def empty_phone(cls, v):
        return None if isinstance(v, str) and not v.strip() else v

    @field_validator("full_name")
    @classmethod
    def strip_name(cls, v: str) -> str:
        return v.strip()

    @field_validator("email")
    @classmethod
    def lower_email(cls, v: str) -> str:
        return v.lower()


class LoginIn(BaseModel):
    identifier: str = Field(min_length=1, max_length=254, description="Email address or username")
    password: str = Field(min_length=1, max_length=128)

    @field_validator("identifier")
    @classmethod
    def normalize(cls, v: str) -> str:
        return v.strip().lower()


class ForgotPasswordIn(BaseModel):
    identifier: str = Field(min_length=1, max_length=254, description="Email address or username")

    @field_validator("identifier")
    @classmethod
    def normalize(cls, v: str) -> str:
        return v.strip().lower()


class ResetPasswordIn(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    new_password: str = Field(min_length=12, max_length=72)

    @field_validator("new_password")
    @classmethod
    def strong_password(cls, v: str) -> str:
        return _validate_password_strength(v)


class MessageOut(BaseModel):
    message: str


class UserOut(ORM):
    id: uuid.UUID
    email: str
    username: str | None
    full_name: str
    phone: str | None
    role: Role
    status: UserStatus
    last_login_at: datetime | None
    created_at: datetime


class UserBrief(ORM):
    id: uuid.UUID
    email: str
    full_name: str


# ---------- Accounts / onboarding ----------
class AccountCreateIn(BaseModel):
    type: AccountType
    currency: Literal["USD", "EUR", "GBP", "INR"] = "USD"
    nickname: str | None = Field(default=None, max_length=60)


class AccountOut(ORM):
    id: uuid.UUID
    account_number: str
    nickname: str | None
    type: AccountType
    currency: str
    balance: Decimal
    status: AccountStatus
    review_note: str | None
    reviewed_at: datetime | None
    created_at: datetime


class AdminAccountOut(AccountOut):
    owner: UserBrief
    reviewed_by: UserBrief | None


class AccountReviewIn(BaseModel):
    decision: Literal["approve", "reject"]
    note: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def note_required_for_reject(self):
        if self.decision == "reject" and not (self.note and self.note.strip()):
            raise ValueError("A note is required when rejecting an application")
        return self


# ---------- Admin user management ----------
class AdminUserCreateIn(RegisterIn):
    role: Role = Role.ACCOUNT_HOLDER


class AdminUserUpdateIn(BaseModel):
    role: Role | None = None
    status: UserStatus | None = None


# ---------- Audit ----------
class AuditLogOut(ORM):
    id: int
    actor_id: uuid.UUID | None
    actor_email: str | None
    action: str
    entity_type: str | None
    entity_id: str | None
    details: dict | None
    ip: str | None
    created_at: datetime


# ---------- Common ----------
class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int


class StatsOut(BaseModel):
    users_by_role: dict[str, int]
    accounts_by_status: dict[str, int]
    pending_applications: int
    total_active_balance: dict[str, Decimal]
    transactions_total: int
    transactions_last_24h: int
    recent_activity: list[AuditLogOut]


# ---------- Transactions ----------
MAX_AMOUNT = Decimal("1000000000")

Amount = Field(gt=0, le=MAX_AMOUNT, max_digits=12, decimal_places=2,
               description="Positive amount with at most 2 decimals")


class MoneyIn(BaseModel):
    amount: Decimal = Amount
    description: str | None = Field(default=None, max_length=200)

    @field_validator("description")
    @classmethod
    def strip_description(cls, v: str | None) -> str | None:
        return (v or "").strip() or None


class TransferIn(MoneyIn):
    from_account_id: uuid.UUID
    to_account_number: str = Field(pattern=r"^\d{12}$")

    @field_validator("to_account_number", mode="before")
    @classmethod
    def strip_spaces(cls, v):
        return v.replace(" ", "") if isinstance(v, str) else v


class AccountRef(ORM):
    id: uuid.UUID
    account_number: str
    nickname: str | None
    type: AccountType


class UserRef(ORM):
    id: uuid.UUID
    email: str
    username: str | None
    full_name: str


class TransactionOut(BaseModel):
    id: uuid.UUID
    reference: str
    type: TransactionType
    amount: Decimal
    currency: str
    balance_after: Decimal
    description: str | None
    created_at: datetime
    transfer_id: uuid.UUID | None
    account: AccountRef
    counterparty_account_number: str | None
    # Oversight-only fields (None for account holders).
    owner: UserRef | None = None
    initiated_by: UserRef | None = None
    counterparty_owner: UserRef | None = None


class TransferOut(BaseModel):
    transfer_id: uuid.UUID
    debit: TransactionOut
    credit: TransactionOut | None  # hidden from the sender if the destination is someone else's
