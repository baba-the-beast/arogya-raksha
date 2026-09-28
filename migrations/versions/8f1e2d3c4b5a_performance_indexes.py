"""performance_indexes
Adds composite and demographic query indexes to patients and password_reset_tokens.

Revision ID: 8f1e2d3c4b5a
Revises: 528524d57ee4
Create Date: 2026-09-23 02:47:00.000000

"""
from typing import Sequence, Union
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '8f1e2d3c4b5a'
down_revision: Union[str, Sequence[str], None] = '528524d57ee4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create query performance indexes."""
    with op.batch_alter_table("patients") as batch_op:
        batch_op.create_index("ix_patients_deleted_created", ["deleted_at", "created_at"])
        batch_op.create_index("ix_patients_age_band", ["age_band"])
        batch_op.create_index("ix_patients_gender", ["gender"])

    with op.batch_alter_table("password_reset_tokens") as batch_op:
        batch_op.create_index("ix_password_reset_tokens_user_expires", ["user_id", "expires_at"])


def downgrade() -> None:
    """Drop performance indexes."""
    with op.batch_alter_table("password_reset_tokens") as batch_op:
        batch_op.drop_index("ix_password_reset_tokens_user_expires")

    with op.batch_alter_table("patients") as batch_op:
        batch_op.drop_index("ix_patients_gender")
        batch_op.drop_index("ix_patients_age_band")
        batch_op.drop_index("ix_patients_deleted_created")
