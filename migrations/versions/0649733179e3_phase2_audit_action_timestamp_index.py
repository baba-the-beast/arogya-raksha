"""phase2_audit_action_timestamp_index

Revision ID: 0649733179e3
Revises: eca31617d943
Create Date: 2026-09-23 01:45:19.302271

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0649733179e3'
down_revision: Union[str, Sequence[str], None] = 'eca31617d943'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Phase 2: composite index on audit_logs(action, timestamp) for filter query performance."""
    with op.batch_alter_table("audit_logs") as batch_op:
        batch_op.create_index(
            "ix_audit_logs_action_timestamp", ["action", "timestamp"]
        )


def downgrade() -> None:
    """Phase 2 rollback."""
    with op.batch_alter_table("audit_logs") as batch_op:
        batch_op.drop_index("ix_audit_logs_action_timestamp")
