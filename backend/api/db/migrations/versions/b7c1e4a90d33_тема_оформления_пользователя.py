"""тема оформления пользователя

Revision ID: b7c1e4a90d33
Revises: a1b2c3d4e5f6
Create Date: 2026-09-14 00:00:00.000000

"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b7c1e4a90d33"
down_revision: str | Sequence[str] | None = "a1b2c3d4e5f6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Все, кто был до появления выбора, остаются на тёмной — она была
    единственной."""
    with op.batch_alter_table("app_user") as batch:
        batch.add_column(sa.Column("theme", sa.String(8), nullable=False, server_default="dark"))


def downgrade() -> None:
    with op.batch_alter_table("app_user") as batch:
        batch.drop_column("theme")
