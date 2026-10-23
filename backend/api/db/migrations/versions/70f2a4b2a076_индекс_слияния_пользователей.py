"""Assets: индекс `asset_user.merged_into` — удаление пользователей не просматривает таблицу на каждую строку

Revision ID: 70f2a4b2a076
Revises: 1c1f9acd03bb
Create Date: 2026-10-23 20:00:00.000000

Самоссылка `merged_into` (`SET NULL`) без индекса: удаление каждой учётки искало ссылки на неё
последовательным просмотром `asset_user`. Только индекс; откат его удаляет.
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "70f2a4b2a076"
down_revision: str | Sequence[str] | None = "1c1f9acd03bb"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index("ix_asset_user_merged_into", "asset_user", ["merged_into"])


def downgrade() -> None:
    op.drop_index("ix_asset_user_merged_into", table_name="asset_user")
