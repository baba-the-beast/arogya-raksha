"""phase1_session_version_and_audit_prev_hash_unique

Revision ID: eca31617d943
Revises: 1c53657c3fd2
Create Date: 2026-09-23 01:31:23.429639

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'eca31617d943'
down_revision: Union[str, Sequence[str], None] = '1c53657c3fd2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Phase 1: add session_version to users; add UNIQUE constraint on audit_logs.prev_hash."""
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(
            sa.Column("session_version", sa.Integer(), nullable=False, server_default=sa.text("1"))
        )

    with op.batch_alter_table("audit_logs") as batch_op:
        batch_op.create_unique_constraint(
            "uq_audit_logs_prev_hash", ["prev_hash"]
        )


def downgrade() -> None:
    """Phase 1 rollback."""
    with op.batch_alter_table("audit_logs") as batch_op:
        batch_op.drop_constraint("uq_audit_logs_prev_hash", type_="unique")

    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("session_version")
