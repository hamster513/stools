"""Threat Hunting: ханты, запросы, прогоны, большие ханты, находки, события; ключ настроек siem_kb -> siem_mp

Revision ID: a7c3e91d5b24
Revises: b3c4d5e6f7a8
Create Date: 2026-10-19 12:00:00.000000

Раздел «Охота» в SIEM хранит ханты с PDQL-запросами, ночные прогоны по
датам, большие ханты (длинный период, нарезанный на окна) и их находки
с событиями. Заодно подключение к MaxPatrol становится общим для разделов:
его ключ в `app_setting` переименован из `siem_kb` в `siem_mp`.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a7c3e91d5b24"
down_revision: str | Sequence[str] | None = "b3c4d5e6f7a8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("UPDATE app_setting SET key = 'siem_mp' WHERE key = 'siem_kb'")
    op.create_table(
        "th_hunt",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("code", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("technique_id", sa.String(16), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(255), nullable=False, server_default=""),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "th_query",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("hunt_id", sa.Integer(), sa.ForeignKey("th_hunt.id", ondelete="CASCADE"), nullable=False),
        sa.Column("query_id", sa.String(32), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("query", sa.Text(), nullable=False),
        sa.Column("fields_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("labels_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("limit", sa.Integer(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("hunt_id", "query_id", name="uq_th_query_hunt_query"),
    )
    op.create_table(
        "th_job",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False, index=True),
        sa.Column("stage", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("status", sa.String(16), nullable=False, server_default="running", index=True),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("processed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total", sa.Integer(), nullable=True),
        sa.Column("message", sa.Text(), nullable=False, server_default=""),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_by", sa.String(255), nullable=False, server_default=""),
    )
    op.create_table(
        "th_run",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_date", sa.Date(), nullable=False),
        sa.Column("period_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_to", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued", index=True),
        sa.Column("job_id", sa.Integer(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("queries_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("queries_done", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.UniqueConstraint("target_date", name="uq_th_run_target_date"),
    )
    op.create_table(
        "th_run_query",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.Integer(), sa.ForeignKey("th_run.id", ondelete="CASCADE"), nullable=False),
        sa.Column("query_pk", sa.Integer(), nullable=False),
        sa.Column("hunt_code", sa.String(64), nullable=False),
        sa.Column("query_id", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("events", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.UniqueConstraint("run_id", "query_pk", name="uq_th_run_query"),
    )
    op.create_table(
        "th_deep_hunt",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("hunt_id", sa.Integer(), sa.ForeignKey("th_hunt.id", ondelete="SET NULL"), nullable=True),
        sa.Column("query_id", sa.String(32), nullable=True),
        sa.Column("query", sa.Text(), nullable=False),
        sa.Column("fields_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("labels_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("limit", sa.Integer(), nullable=False, server_default="5000"),
        sa.Column("period_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_to", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued", index=True),
        sa.Column("job_id", sa.Integer(), nullable=True),
        sa.Column("slices_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("slices_done", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_slice_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("events", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("limit_hit_slices", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("partial", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(255), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "th_finding",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("hunt_id", sa.Integer(), sa.ForeignKey("th_hunt.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("hunt_code", sa.String(64), nullable=False, index=True),
        sa.Column("query_id", sa.String(32), nullable=False),
        sa.Column("run_id", sa.Integer(), sa.ForeignKey("th_run.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("deep_id", sa.Integer(), sa.ForeignKey("th_deep_hunt.id", ondelete="CASCADE"), nullable=True, index=True),
        sa.Column("period_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_to", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("limit_hit", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("partial", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("columns_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("events_purged", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
    )
    op.create_table(
        "th_event",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("th_finding.id", ondelete="CASCADE"), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("data_json", sa.Text(), nullable=False),
    )
    op.create_index("ix_th_event_finding_position", "th_event", ["finding_id", "position"])


def downgrade() -> None:
    op.drop_index("ix_th_event_finding_position", table_name="th_event")
    for table in ("th_event", "th_finding", "th_deep_hunt", "th_run_query", "th_run", "th_job", "th_query", "th_hunt"):
        op.drop_table(table)
    op.execute("UPDATE app_setting SET key = 'siem_kb' WHERE key = 'siem_mp'")
