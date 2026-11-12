"""Transactions ledger (append-only).

Revision ID: 0003_transactions
Revises: 0002_username_reset
Create Date: 2026-11-12
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_transactions"
down_revision: str | None = "0002_username_reset"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

transaction_type = postgresql.ENUM(
    "DEPOSIT", "WITHDRAWAL", "TRANSFER_IN", "TRANSFER_OUT", name="transaction_type", create_type=False
)
TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    transaction_type.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "transactions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("reference", sa.String(16), nullable=False, unique=True),
        sa.Column("account_id", sa.Uuid(), sa.ForeignKey("accounts.id"), nullable=False),
        sa.Column("type", transaction_type, nullable=False),
        sa.Column("amount", sa.Numeric(18, 2), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("balance_after", sa.Numeric(18, 2), nullable=False),
        sa.Column("counterparty_account_id", sa.Uuid(), sa.ForeignKey("accounts.id")),
        sa.Column("transfer_id", sa.Uuid()),
        sa.Column("description", sa.String(200)),
        sa.Column("initiated_by_id", sa.Uuid(), sa.ForeignKey("users.id")),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("amount > 0", name="ck_transactions_amount_positive"),
        sa.CheckConstraint("balance_after >= 0", name="ck_transactions_balance_non_negative"),
    )
    op.create_index("ix_transactions_account_id", "transactions", ["account_id"])
    op.create_index("ix_transactions_type", "transactions", ["type"])
    op.create_index("ix_transactions_transfer_id", "transactions", ["transfer_id"])
    op.create_index("ix_transactions_created_at", "transactions", ["created_at"])

    # Ledger entries are permanent: corrections are made with new entries, never by editing.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION ledger_block_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'transactions is append-only (% blocked)', TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        "CREATE TRIGGER transactions_no_update_delete BEFORE UPDATE OR DELETE ON transactions "
        "FOR EACH ROW EXECUTE FUNCTION ledger_block_mutation();"
    )
    op.execute(
        "CREATE TRIGGER transactions_no_truncate BEFORE TRUNCATE ON transactions "
        "FOR EACH STATEMENT EXECUTE FUNCTION ledger_block_mutation();"
    )
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bv_app') THEN
                GRANT SELECT, INSERT ON transactions TO bv_app;
                REVOKE UPDATE, DELETE, TRUNCATE ON transactions FROM bv_app;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bv_readonly') THEN
                GRANT SELECT ON transactions TO bv_readonly;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS transactions_no_truncate ON transactions")
    op.execute("DROP TRIGGER IF EXISTS transactions_no_update_delete ON transactions")
    op.execute("DROP FUNCTION IF EXISTS ledger_block_mutation()")
    op.drop_table("transactions")
    transaction_type.drop(op.get_bind(), checkfirst=True)
