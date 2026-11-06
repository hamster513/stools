"""Внешние сигналы уязвимостей, журнал доставки и решения аналитика."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "b76d23a04ef1"
down_revision = "b47a6d93e102"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("vm_trend_ingest_state",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("collector_id", sa.String(100), nullable=False),
        sa.Column("epoch", sa.String(100), nullable=False), sa.Column("generation", sa.String(36), nullable=False),
        sa.Column("batch_until", sa.BigInteger(), nullable=False),
        sa.Column("active_generation", sa.String(36)), sa.Column("cursor", sa.BigInteger(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True)))
    op.create_table("vm_trend_source", sa.Column("generation", sa.String(36), primary_key=True),
        sa.Column("external_id", sa.String(100), primary_key=True), sa.Column("data", postgresql.JSONB(), nullable=False))
    op.create_table("vm_trend_event_receipt", sa.Column("generation", sa.String(36), primary_key=True),
        sa.Column("seq", sa.BigInteger(), primary_key=True), sa.Column("data", postgresql.JSONB(), nullable=False))
    op.create_table("vm_trend_publication", sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("generation", sa.String(36), nullable=False), sa.Column("external_id", sa.String(100), nullable=False),
        sa.Column("source_id", sa.String(100), nullable=False), sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("data", postgresql.JSONB(), nullable=False), sa.Column("retracted", sa.Boolean(), nullable=False),
        sa.Column("processing", sa.String(16), nullable=False), sa.Column("analysis", postgresql.JSONB(), nullable=False),
        sa.Column("error", sa.Text()), sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("generation", "external_id", name="uq_vm_trend_publication"))
    op.create_index("ix_vm_trend_publication_generation", "vm_trend_publication", ["generation"])
    op.create_index("ix_vm_trend_publication_processing", "vm_trend_publication", ["processing"])
    op.create_table("vm_trend_card", sa.Column("id", sa.String(120), primary_key=True),
        sa.Column("title", sa.Text(), nullable=False), sa.Column("status", sa.String(16), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("active_until", sa.DateTime(timezone=True)), sa.Column("last_event_at", sa.DateTime(timezone=True)),
        sa.Column("reason", sa.String(40), nullable=False), sa.Column("independent_sources", sa.Integer(), nullable=False))
    op.create_index("ix_vm_trend_card_active_until", "vm_trend_card", ["active_until"])
    op.create_table("vm_trend_evidence", sa.Column("card_id", sa.String(120), sa.ForeignKey("vm_trend_card.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("publication_id", sa.Integer(), sa.ForeignKey("vm_trend_publication.id", ondelete="CASCADE"), primary_key=True))
    op.create_table("vm_trend_review", sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("card_id", sa.String(120), sa.ForeignKey("vm_trend_card.id", ondelete="CASCADE"), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decision", postgresql.JSONB(), nullable=False))
    op.create_index("ix_vm_trend_review_card_id", "vm_trend_review", ["card_id"])


def downgrade():
    for table in ("vm_trend_review", "vm_trend_evidence", "vm_trend_card", "vm_trend_publication",
                  "vm_trend_event_receipt", "vm_trend_source", "vm_trend_ingest_state"):
        op.drop_table(table)
