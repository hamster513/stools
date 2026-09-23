"""секреты и хеш сессий

Токен сессии теперь хранится как SHA-256 (api/crypto.py): старые строки
содержат сырые токены и больше не находятся — удаляем их, все входят
заново. Пароли подключений AD и KSC хранятся зашифрованными
(`enc:v1:<Fernet>`), шифротекст длиннее 255 символов для длинных паролей —
колонки становятся text. Сами значения не трогаем: открытые пароли
шифруются при следующем сохранении подключения.

Downgrade возвращает varchar(255) и падает, если в базе есть шифротекст
длиннее 255 символов — это пароль от 128 байт (в UTF-8) и длиннее. Перед
откатом такие пароли нужно ввести заново короче или очистить эти строки
(`UPDATE ad_connection SET password = '' WHERE length(password) > 255`,
то же для ksc_connection) и ввести пароль после отката.

Revision ID: e6f7a8b9c0d1
Revises: d5e6f7a8b9c0
Create Date: 2026-09-23 00:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e6f7a8b9c0d1"
down_revision: str | Sequence[str] | None = "d5e6f7a8b9c0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = ("ad_connection", "ksc_connection")


def upgrade() -> None:
    op.execute("DELETE FROM session")
    for table in TABLES:
        op.alter_column(table, "password", type_=sa.Text(), existing_type=sa.String(255), existing_nullable=False)


def downgrade() -> None:
    #: Хеши в cookie не превращаются обратно в токены — сессии снова сбрасываются.
    op.execute("DELETE FROM session")
    for table in TABLES:
        op.alter_column(table, "password", type_=sa.String(255), existing_type=sa.Text(), existing_nullable=False)
