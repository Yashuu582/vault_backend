"""Username sign-in and password reset tokens.

Revision ID: 0002_username_reset
Revises: 0001_initial
Create Date: 2026-11-11
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_username_reset"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.add_column("users", sa.Column("username", sa.String(50), nullable=True))
    op.create_index("ix_users_username", "users", ["username"], unique=True)

    op.create_table(
        "password_reset_tokens",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("used_at", TS),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("ip", sa.String(64)),
    )
    op.create_index("ix_password_reset_tokens_user_id", "password_reset_tokens", ["user_id"])

    # Keep the optional least-privileged role (sql/db_roles.sql) working if it exists.
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bv_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON password_reset_tokens TO bv_app;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    op.drop_table("password_reset_tokens")
    op.drop_index("ix_users_username", table_name="users")
    op.drop_column("users", "username")
