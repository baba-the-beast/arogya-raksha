"""phase4_auth_hardening_totp_password_reset

Revision ID: 100c408e589d
Revises: 0649733179e3
Create Date: 2026-09-23 02:20:52.662194

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '100c408e589d'
down_revision: Union[str, Sequence[str], None] = '0649733179e3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Phase 4: add totp_secret, totp_enabled to users; create password_reset_tokens table."""
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("totp_secret", sa.String(length=64), nullable=True))
        batch_op.add_column(
            sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.text("0"))
        )

    op.create_table(
        "password_reset_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.text("0")),
    )
    with op.batch_alter_table("password_reset_tokens") as batch_op:
        batch_op.create_index("ix_password_reset_tokens_user_id", ["user_id"])
        batch_op.create_index("ix_password_reset_tokens_token_hash", ["token_hash"], unique=True)


def downgrade() -> None:
    """Phase 4 rollback."""
    with op.batch_alter_table("password_reset_tokens") as batch_op:
        batch_op.drop_index("ix_password_reset_tokens_token_hash")
        batch_op.drop_index("ix_password_reset_tokens_user_id")
    op.drop_table("password_reset_tokens")

    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("totp_enabled")
        batch_op.drop_column("totp_secret")
