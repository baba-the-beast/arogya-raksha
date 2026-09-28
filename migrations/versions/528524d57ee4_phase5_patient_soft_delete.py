"""phase5_patient_soft_delete

Revision ID: 528524d57ee4
Revises: 100c408e589d
Create Date: 2026-09-23 02:28:27.441614

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '528524d57ee4'
down_revision: Union[str, Sequence[str], None] = '100c408e589d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Phase 5: add deleted_at column and index to patients table."""
    with op.batch_alter_table("patients") as batch_op:
        batch_op.add_column(sa.Column("deleted_at", sa.DateTime(), nullable=True))
        batch_op.create_index("ix_patients_deleted_at", ["deleted_at"])


def downgrade() -> None:
    """Phase 5 rollback."""
    with op.batch_alter_table("patients") as batch_op:
        batch_op.drop_index("ix_patients_deleted_at")
        batch_op.drop_column("deleted_at")
