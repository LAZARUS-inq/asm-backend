"""add users.plan_expires_at

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-06-01

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b2c3d4e5f6a7"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Idempotent — column may already exist if added manually on Railway.
    op.execute(
        sa.text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
            "plan_expires_at TIMESTAMP WITH TIME ZONE"
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text("ALTER TABLE users DROP COLUMN IF EXISTS plan_expires_at")
    )
