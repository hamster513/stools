"""зона External в справочнике зон — сети с публичными адресами (из RackTables)

Revision ID: d8e9f0a1b2c3
Revises: c7d8e9f0a1b2
Create Date: 2026-10-13 00:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d8e9f0a1b2c3"
down_revision: str | Sequence[str] | None = "c7d8e9f0a1b2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Зону могли завести руками раньше — тогда ничего не вставляется.
    op.execute(sa.text(
        "INSERT INTO asset_zone (name, title, description) SELECT 'External', 'External', 'внешние (публичные) адреса' "
        "WHERE NOT EXISTS (SELECT 1 FROM asset_zone WHERE name = 'External')"
    ))


def downgrade() -> None:
    # Зона остаётся: на неё могут ссылаться сети.
    pass
