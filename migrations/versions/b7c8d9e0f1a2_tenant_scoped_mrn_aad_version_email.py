"""tenant_scoped_mrn_aad_version_email
Makes patient IDs unique per tenant instead of globally, widens patient_id to the model's 64
chars, adds patients.crypto_schema (version-bound AAD), adds users.email (reset delivery), and
assigns existing doctor-authored records to their author as attending physician.

Revision ID: b7c8d9e0f1a2
Revises: a1b2c3d4e5f6
Create Date: 2026-09-28 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'b7c8d9e0f1a2'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("email", sa.String(length=255), nullable=True))

    with op.batch_alter_table("patients") as batch_op:
        batch_op.add_column(sa.Column("crypto_schema", sa.Integer(), nullable=False, server_default="1"))
        batch_op.alter_column("patient_id", existing_type=sa.String(length=32), type_=sa.String(length=64),
                              existing_nullable=False)
        batch_op.drop_index("ix_patients_patient_id")
        batch_op.create_index("ix_patients_patient_id", ["patient_id"], unique=False)
        batch_op.create_index("uq_patients_tenant_patient_id", ["tenant_id", "patient_id"], unique=True)

    # Care-team access is now driven by assigned_doctor_id; keep doctor-authored records editable
    # by their author.
    op.execute(
        "UPDATE patients SET assigned_doctor_id = created_by "
        "WHERE assigned_doctor_id IS NULL "
        "AND created_by IN (SELECT id FROM users WHERE role = 'Doctor')"
    )


def downgrade() -> None:
    with op.batch_alter_table("patients") as batch_op:
        batch_op.drop_index("uq_patients_tenant_patient_id")
        batch_op.drop_index("ix_patients_patient_id")
        batch_op.create_index("ix_patients_patient_id", ["patient_id"], unique=True)
        batch_op.alter_column("patient_id", existing_type=sa.String(length=64), type_=sa.String(length=32),
                              existing_nullable=False)
        batch_op.drop_column("crypto_schema")

    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("email")
