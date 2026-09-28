"""high_assurance_occ_outbox_mfa
Adds OCC version_id to patients, encrypted TOTP fields to users, and creates outbox_events table.

Revision ID: 9a2b3c4d5e6f
Revises: 8f1e2d3c4b5a
Create Date: 2026-09-23 03:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '9a2b3c4d5e6f'
down_revision: Union[str, Sequence[str], None] = '8f1e2d3c4b5a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add version_id to patients for Optimistic Concurrency Control (P0-8)
    with op.batch_alter_table("patients") as batch_op:
        batch_op.add_column(sa.Column("version_id", sa.Integer(), nullable=False, server_default="1"))

    # 2. Add encrypted TOTP storage columns to users (P0-4)
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("totp_secret_encrypted", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("totp_secret_nonce", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("totp_secret_tag", sa.String(length=64), nullable=True))

    # 3. Create outbox_events table for Transactional Outbox (P0-7)
    op.create_table(
        "outbox_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_retries", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("idempotency_key", sa.String(length=128), nullable=True),
        sa.Column("error_log", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("processed_at", sa.DateTime(), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_outbox_events_event_type", "outbox_events", ["event_type"])
    op.create_index("ix_outbox_events_status", "outbox_events", ["status"])
    op.create_index("ix_outbox_events_idempotency_key", "outbox_events", ["idempotency_key"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_outbox_events_idempotency_key", table_name="outbox_events")
    op.drop_index("ix_outbox_events_status", table_name="outbox_events")
    op.drop_index("ix_outbox_events_event_type", table_name="outbox_events")
    op.drop_table("outbox_events")

    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("totp_secret_tag")
        batch_op.drop_column("totp_secret_nonce")
        batch_op.drop_column("totp_secret_encrypted")

    with op.batch_alter_table("patients") as batch_op:
        batch_op.drop_column("version_id")
