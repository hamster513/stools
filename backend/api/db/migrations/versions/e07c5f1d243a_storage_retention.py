"""Safe storage retention previews, audit, and replay hashes."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = 'e07c5f1d243a'
down_revision = 'c85a3d9b021e'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('vm_trend_event_receipt', sa.Column('payload_hash', sa.String(64), nullable=True))
    op.add_column('vm_trend_event_receipt', sa.Column('received_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))
    op.alter_column('vm_trend_event_receipt', 'data', nullable=True)
    op.add_column('vm_trend_ingest_state', sa.Column('snapshot_id', sa.String(36), nullable=True))
    op.add_column('vm_trend_ingest_state', sa.Column('snapshot_baseline', sa.BigInteger(), nullable=True))
    op.create_table('platform_retention_preview',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('consumed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('policy', postgresql.JSONB(), nullable=False), sa.Column('data', postgresql.JSONB(), nullable=False))
    op.create_table('platform_retention_run',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('policy', postgresql.JSONB(), nullable=False), sa.Column('data', postgresql.JSONB(), nullable=False))
    op.create_index('ix_platform_retention_run_started_at', 'platform_retention_run', ['started_at'])
    op.execute("""INSERT INTO platform_schedule(module,kind,target_id,interval_hours,weekdays,run_time,enabled,next_run_at)
        VALUES ('platform','storage_cleanup',0,24,'0123456','03:30',false,NULL)
        ON CONFLICT (module,kind,target_id) DO NOTHING""")


def downgrade():
    # Never discard the only proof remaining after payload compaction.
    if op.get_bind().execute(sa.text("SELECT EXISTS(SELECT 1 FROM vm_trend_event_receipt WHERE data IS NULL)")).scalar():
        raise RuntimeError('Cannot downgrade after receipt compaction; restore the pre-retention backup')
    op.execute("DELETE FROM platform_schedule WHERE module='platform' AND kind='storage_cleanup' AND target_id=0")
    op.drop_table('platform_retention_run')
    op.drop_table('platform_retention_preview')
    op.drop_column('vm_trend_ingest_state', 'snapshot_baseline')
    op.drop_column('vm_trend_ingest_state', 'snapshot_id')
    op.drop_column('vm_trend_event_receipt', 'received_at')
    op.drop_column('vm_trend_event_receipt', 'payload_hash')
