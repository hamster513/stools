"""режим последнего скана сети: last_scan_icmp — шёл ли скан с ICMP (False — «только порты», NULL — не сканировали)

Revision ID: f3a4b5c6d7e8
Revises: e2f3a4b5c6d7
Create Date: 2026-10-01 18:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f3a4b5c6d7e8"
down_revision: str | Sequence[str] | None = "e2f3a4b5c6d7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("network", sa.Column("last_scan_icmp", sa.Boolean(), nullable=True))


def downgrade() -> None:
    op.drop_column("network", "last_scan_icmp")
