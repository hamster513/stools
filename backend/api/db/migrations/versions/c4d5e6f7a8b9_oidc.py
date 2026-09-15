"""oidc

Revision ID: c4d5e6f7a8b9
Revises: b7c1e4a90d33
Create Date: 2026-09-14 00:00:00.000000

Откат упадёт, если в базе есть учётки провайдера: у них password_hash
пустой, а downgrade() возвращает колонке NOT NULL. Перед откатом такие
учётки нужно удалить или перевести на локальный пароль.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c4d5e6f7a8b9"
down_revision: str | Sequence[str] | None = "b7c1e4a90d33"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("app_user") as batch:
        batch.add_column(sa.Column("auth_source", sa.String(8), nullable=False, server_default="local"))
        batch.add_column(sa.Column("oidc_subject", sa.String(255), nullable=True))
        batch.alter_column("password_hash", existing_type=sa.String(255), nullable=True)
        batch.create_unique_constraint("uq_app_user_oidc_subject", ["oidc_subject"])
    op.create_table(
        "oidc_login_state",
        sa.Column("state", sa.String(64), primary_key=True),
        sa.Column("nonce", sa.String(64), nullable=False),
        sa.Column("code_verifier", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("oidc_login_state")
    with op.batch_alter_table("app_user") as batch:
        batch.drop_constraint("uq_app_user_oidc_subject", type_="unique")
        batch.alter_column("password_hash", existing_type=sa.String(255), nullable=False)
        batch.drop_column("oidc_subject")
        batch.drop_column("auth_source")
