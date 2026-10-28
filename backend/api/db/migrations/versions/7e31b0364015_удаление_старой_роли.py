"""Удаление старой роли пользователя

Revision ID: 7e31b0364015
Revises: a7c3e9f1b204
Create Date: 2026-10-27 14:00:00.000000

Спека ролей §2 «Миграция», шаг 5 (миграция B): права дают только группы, колонка `app_user.role`
больше никем не читается и удаляется. Ключ `group_roles` из JSON настроек OIDC убрала миграция A.

Откат возвращает колонку по максимуму из групп пользователя: `platform=admin` → admin, иначе
`write` и выше где-либо → analyst, иначе auditor; пользователь без групп — auditor.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "7e31b0364015"
down_revision: str | Sequence[str] | None = "a7c3e9f1b204"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Уровни пользователя по всем его группам — для подзапросов отката.
_LEVELS = (
    "SELECT 1 FROM access_membership m JOIN access_group g ON g.id = m.group_id "
    "JOIN access_role_level l ON l.role_id = g.role_id WHERE m.user_id = u.id"
)


def upgrade() -> None:
    op.drop_column("app_user", "role")


def downgrade() -> None:
    op.add_column("app_user", sa.Column("role", sa.String(16), nullable=False, server_default="auditor"))
    op.execute(
        "UPDATE app_user u SET role = CASE "
        f"WHEN EXISTS ({_LEVELS} AND l.area = 'platform' AND l.level = 'admin') THEN 'admin' "
        f"WHEN EXISTS ({_LEVELS} AND l.level IN ('write', 'admin')) THEN 'analyst' "
        "ELSE 'auditor' END"
    )
    # Умолчание колонки — как до миграции A (a1b2c3d4e5f6): новые строки старый код заводил администраторами.
    op.alter_column("app_user", "role", server_default="admin", existing_type=sa.String(16), existing_nullable=False)
