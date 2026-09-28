"""Tenant-scope transactional outbox events.

Revision ID: c3d4e5f6a7b8
Revises: b7c8d9e0f1a2
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "c3d4e5f6a7b8"
down_revision: Union[str, Sequence[str], None] = "b7c8d9e0f1a2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Existing events predate tenant attribution and belong to the historical default
    # tenant. New writes always receive the authenticated tenant from the server context.
    with op.batch_alter_table("outbox_events") as batch_op:
        batch_op.add_column(sa.Column("tenant_id", sa.String(length=32), nullable=False, server_default="tenant-default"))
        batch_op.create_foreign_key("fk_outbox_events_tenant_id", "tenants", ["tenant_id"], ["id"])
        batch_op.create_index("ix_outbox_events_tenant_id", ["tenant_id"], unique=False)
        batch_op.alter_column("tenant_id", server_default=None)


def downgrade() -> None:
    with op.batch_alter_table("outbox_events") as batch_op:
        batch_op.drop_index("ix_outbox_events_tenant_id")
        batch_op.drop_constraint("fk_outbox_events_tenant_id", type_="foreignkey")
        batch_op.drop_column("tenant_id")
