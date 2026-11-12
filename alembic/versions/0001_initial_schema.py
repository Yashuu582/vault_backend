"""Initial schema: users, accounts, refresh tokens, append-only audit log.

Revision ID: 0001_initial
Revises:
Create Date: 2026-11-10
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

user_role = postgresql.ENUM("ADMIN", "AUDITOR", "ACCOUNT_HOLDER", name="user_role", create_type=False)
user_status = postgresql.ENUM("ACTIVE", "SUSPENDED", name="user_status", create_type=False)
account_type = postgresql.ENUM("CHECKING", "SAVINGS", "BUSINESS", name="account_type", create_type=False)
account_status = postgresql.ENUM(
    "PENDING_APPROVAL", "ACTIVE", "REJECTED", "FROZEN", "CLOSED", name="account_status", create_type=False
)
ENUMS = (user_role, user_status, account_type, account_status)
TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    bind = op.get_bind()
    for enum in ENUMS:
        enum.create(bind, checkfirst=True)

    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("password_hash", sa.String(100), nullable=False),
        sa.Column("full_name", sa.String(120), nullable=False),
        sa.Column("phone", sa.String(32)),
        sa.Column("role", user_role, nullable=False, server_default="ACCOUNT_HOLDER"),
        sa.Column("status", user_status, nullable=False, server_default="ACTIVE"),
        sa.Column("last_login_at", TS),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", TS, nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "accounts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("account_number", sa.String(12), nullable=False, unique=True),
        sa.Column("nickname", sa.String(60)),
        sa.Column("type", account_type, nullable=False),
        sa.Column("currency", sa.String(3), nullable=False, server_default="USD"),
        sa.Column("balance", sa.Numeric(18, 2), nullable=False, server_default="0"),
        sa.Column("status", account_status, nullable=False, server_default="PENDING_APPROVAL"),
        sa.Column("owner_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("reviewed_by_id", sa.Uuid(), sa.ForeignKey("users.id")),
        sa.Column("reviewed_at", TS),
        sa.Column("review_note", sa.String(500)),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", TS, nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("balance >= 0", name="ck_accounts_balance_non_negative"),
        sa.CheckConstraint("currency ~ '^[A-Z]{3}$'", name="ck_accounts_currency_iso"),
    )
    op.create_index("ix_accounts_owner_id", "accounts", ["owner_id"])
    op.create_index("ix_accounts_status", "accounts", ["status"])

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("family_id", sa.Uuid(), nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("revoked_at", TS),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("user_agent", sa.String(255)),
        sa.Column("ip", sa.String(64)),
    )
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])
    op.create_index("ix_refresh_tokens_family_id", "refresh_tokens", ["family_id"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), primary_key=True),
        sa.Column("actor_id", sa.Uuid(), sa.ForeignKey("users.id")),
        sa.Column("actor_email", sa.String(254)),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("entity_type", sa.String(32)),
        sa.Column("entity_id", sa.String(64)),
        sa.Column("details", postgresql.JSONB()),
        sa.Column("ip", sa.String(64)),
        sa.Column("user_agent", sa.String(255)),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_audit_logs_actor_id", "audit_logs", ["actor_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])

    # Audit log is append-only, enforced in the database regardless of which role connects.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION audit_logs_block_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_logs is append-only (% blocked)', TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        "CREATE TRIGGER audit_logs_no_update_delete BEFORE UPDATE OR DELETE ON audit_logs "
        "FOR EACH ROW EXECUTE FUNCTION audit_logs_block_mutation();"
    )
    op.execute(
        "CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs "
        "FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_block_mutation();"
    )

    # If the least-privileged app role exists (sql/db_roles.sql), restrict it on audit_logs.
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bv_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON users, accounts, refresh_tokens TO bv_app;
                GRANT SELECT, INSERT ON audit_logs TO bv_app;
                REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM bv_app;
                GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO bv_app;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bv_readonly') THEN
                GRANT SELECT ON users, accounts, audit_logs TO bv_readonly;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_logs_no_truncate ON audit_logs")
    op.execute("DROP TRIGGER IF EXISTS audit_logs_no_update_delete ON audit_logs")
    op.execute("DROP FUNCTION IF EXISTS audit_logs_block_mutation()")
    op.drop_table("audit_logs")
    op.drop_table("refresh_tokens")
    op.drop_table("accounts")
    op.drop_table("users")
    bind = op.get_bind()
    for enum in reversed(ENUMS):
        enum.drop(bind, checkfirst=True)
