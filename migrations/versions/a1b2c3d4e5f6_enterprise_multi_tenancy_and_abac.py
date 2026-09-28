"""enterprise_multi_tenancy_and_abac
Creates tenants table, adds tenant_id and totp_key_version to users,
tenant_id, department, assigned_doctor_id to patients, and tenant_id to audit_logs.

Revision ID: a1b2c3d4e5f6
Revises: 9a2b3c4d5e6f
Create Date: 2026-09-23 05:00:00.000000

"""
from typing import Sequence, Union
from datetime import UTC, datetime

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = '9a2b3c4d5e6f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create tenants table
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("code", sa.String(length=32), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_tenants_code", "tenants", ["code"], unique=True)

    # 2. Seed default tenant
    tenants_table = sa.table(
        "tenants",
        sa.column("id", sa.String),
        sa.column("name", sa.String),
        sa.column("code", sa.String),
        sa.column("is_active", sa.Boolean),
        sa.column("created_at", sa.DateTime),
    )
    op.bulk_insert(
        tenants_table,
        [
            {
                "id": "tenant-default",
                "name": "Default Health Clinic",
                "code": "DEF-01",
                "is_active": True,
                "created_at": datetime.now(UTC),
            }
        ]
    )

    # 3. Add columns to users
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("tenant_id", sa.String(length=32), nullable=False, server_default="tenant-default"))
        batch_op.add_column(sa.Column("totp_key_version", sa.Integer(), nullable=False, server_default="1"))
        batch_op.create_index("ix_users_tenant_id", ["tenant_id"])

    # 4. Add columns to patients
    with op.batch_alter_table("patients") as batch_op:
        batch_op.add_column(sa.Column("tenant_id", sa.String(length=32), nullable=False, server_default="tenant-default"))
        batch_op.add_column(sa.Column("department", sa.String(length=50), nullable=True, server_default="General"))
        batch_op.add_column(sa.Column("assigned_doctor_id", sa.Integer(), nullable=True))
        batch_op.create_index("ix_patients_tenant_id", ["tenant_id"])
        batch_op.create_index("ix_patients_assigned_doctor_id", ["assigned_doctor_id"])

    # 5. Add columns to audit_logs
    with op.batch_alter_table("audit_logs") as batch_op:
        batch_op.add_column(sa.Column("tenant_id", sa.String(length=32), nullable=True, server_default="tenant-default"))
        batch_op.create_index("ix_audit_logs_tenant_id", ["tenant_id"])


def downgrade() -> None:
    with op.batch_alter_table("audit_logs") as batch_op:
        batch_op.drop_index("ix_audit_logs_tenant_id")
        batch_op.drop_column("tenant_id")

    with op.batch_alter_table("patients") as batch_op:
        batch_op.drop_index("ix_patients_assigned_doctor_id")
        batch_op.drop_index("ix_patients_tenant_id")
        batch_op.drop_column("assigned_doctor_id")
        batch_op.drop_column("department")
        batch_op.drop_column("tenant_id")

    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_index("ix_users_tenant_id")
        batch_op.drop_column("totp_key_version")
        batch_op.drop_column("tenant_id")

    op.drop_index("ix_tenants_code", table_name="tenants")
    op.drop_table("tenants")
