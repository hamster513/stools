"""журнал: группы пользователя целиком

`audit_event.role` теперь хранит группы пользователя через запятую (спека ролей §2), а не
короткое имя роли: «Администраторы, Аналитики» или «<группа> (OIDC)» в String(16) не влезают,
а обрезанная строка искажала бы в журнале, какие права были у пользователя. Колонка — Text: имя
группы до 255 символов, групп у пользователя может быть несколько.

Откат обрезает значения до 16 символов — иначе сужение колонки упало бы на длинных строках.

Revision ID: a7c3e9f1b204
Revises: e5a1c7b3d902
Create Date: 2026-10-27 13:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a7c3e9f1b204"
down_revision: str | Sequence[str] | None = "e5a1c7b3d902"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column("audit_event", "role", type_=sa.Text(), existing_type=sa.String(16), existing_nullable=True)


def downgrade() -> None:
    op.execute("UPDATE audit_event SET role = left(role, 16) WHERE length(role) > 16")
    op.alter_column("audit_event", "role", type_=sa.String(16), existing_type=sa.Text(), existing_nullable=True)
