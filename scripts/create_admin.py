"""Create the first admin (or any staff user).

Usage (from the Backend folder):
    python -m scripts.create_admin --username admin --email admin@example.com --name "Vault Admin"
    python -m scripts.create_admin --email auditor@example.com --name "Audit Team" --role AUDITOR

The password is read from BV_ADMIN_PASSWORD, or prompted for, so it never lands in shell history.
Users created here may sign in with their username or their email.

Note: email validation rejects reserved domains such as .local / .test - use a real-looking domain.
"""

import argparse
import getpass
import os
import sys

from pydantic import BaseModel, EmailStr, ValidationError, field_validator
from sqlalchemy import select

from app import audit
from app.db import SessionLocal
from app.models import Role, User
from app.schemas import _validate_password_strength, normalize_username
from app.security import hash_password

MIN_SEED_PASSWORD = 8


class SeedUser(BaseModel):
    email: EmailStr
    full_name: str
    username: str | None = None

    @field_validator("email")
    @classmethod
    def lower_email(cls, v: str) -> str:
        return v.lower()

    @field_validator("username")
    @classmethod
    def check_username(cls, v: str | None) -> str | None:
        return normalize_username(v)


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a BalanceVault staff user")
    parser.add_argument("--email", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--username", default=None)
    parser.add_argument("--role", choices=[r.value for r in Role], default=Role.ADMIN.value)
    args = parser.parse_args()

    try:
        data = SeedUser(email=args.email, full_name=args.name, username=args.username)
    except ValidationError as exc:
        print(exc, file=sys.stderr)
        return 1

    password = os.environ.get("BV_ADMIN_PASSWORD") or getpass.getpass("Password: ")
    if len(password) < MIN_SEED_PASSWORD or len(password.encode()) > 72:
        print(f"Password must be {MIN_SEED_PASSWORD}-72 characters.", file=sys.stderr)
        return 1
    try:
        _validate_password_strength(password)
    except ValueError as exc:
        print(f"WARNING: weak admin password ({exc}). Change it before using this outside local development.")

    with SessionLocal() as db:
        existing = db.scalar(select(User).where(User.email == data.email))
        if existing is None and data.username:
            existing = db.scalar(select(User).where(User.username == data.username))

        if existing is not None:
            # Idempotent: never overwrite a password. Only attach a missing username.
            if data.username and existing.username is None and not db.scalar(
                select(User.id).where(User.username == data.username)
            ):
                existing.username = data.username
                db.commit()
                print(f"User {existing.email} already exists - set username '{data.username}'.")
            else:
                print(f"User {existing.email} already exists - nothing to do.")
            return 0

        role = Role(args.role)
        user = User(email=data.email, username=data.username, full_name=data.full_name,
                    password_hash=hash_password(password), role=role)
        db.add(user)
        db.flush()
        audit.record(db, "user.created", actor_email="cli", entity_type="user", entity_id=user.id,
                     details={"email": user.email, "username": user.username, "role": role.value,
                              "via": "create_admin script"})
        db.commit()
        print(f"Created {role.value} user {user.username or user.email}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
