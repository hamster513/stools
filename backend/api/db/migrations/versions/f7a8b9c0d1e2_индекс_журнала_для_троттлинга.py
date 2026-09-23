"""индекс журнала для троттлинга входа

Троттлинг входа (api/routers/auth.py) на каждую попытку считает неудачные
входы за 15 минут: `path = '/api/auth/login' AND status = 401 AND at >= …`.
Составной индекс держит этот запрос дешёвым при большом журнале.

Revision ID: f7a8b9c0d1e2
Revises: e6f7a8b9c0d1
Create Date: 2026-09-23 00:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "f7a8b9c0d1e2"
down_revision: str | Sequence[str] | None = "e6f7a8b9c0d1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index("ix_audit_event_path_status_at", "audit_event", ["path", "status", "at"])


def downgrade() -> None:
    op.drop_index("ix_audit_event_path_status_at", table_name="audit_event")
