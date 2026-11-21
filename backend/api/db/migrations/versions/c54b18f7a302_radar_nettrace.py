"""NetTrace connection, inventory snapshots and persistent path evaluations."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = 'c54b18f7a302'
down_revision = 'b43a07e692f1'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('radar_nettrace_config',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('url', sa.String(1024), nullable=False), sa.Column('token_encrypted', sa.Text(), nullable=False),
        sa.Column('ca_pem', sa.Text(), nullable=False), sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('generation', sa.Integer(), nullable=False), sa.Column('latest_snapshot_id', sa.Integer()),
        sa.Column('synced_at', sa.DateTime(timezone=True)), sa.Column('next_request_at', sa.DateTime(timezone=True)),
        sa.Column('next_evaluation_at', sa.DateTime(timezone=True)))
    op.create_table('radar_nettrace_snapshot',
        sa.Column('id', sa.Integer(), primary_key=True), sa.Column('generation', sa.Integer(), nullable=False),
        sa.Column('snapshot_set_id', sa.String(64), nullable=False), sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('snapshot_set', postgresql.JSONB(), nullable=False), sa.Column('device_count', sa.Integer(), nullable=False),
        sa.Column('warnings', postgresql.JSONB(), nullable=False))
    op.create_table('radar_nettrace_device',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('snapshot_id', sa.Integer(), sa.ForeignKey('radar_nettrace_snapshot.id', ondelete='CASCADE'), nullable=False),
        sa.Column('device_id', sa.String(64), nullable=False), sa.Column('name', sa.String(255), nullable=False),
        sa.Column('document', postgresql.JSONB(), nullable=False))
    op.create_table('radar_nettrace_evaluation',
        sa.Column('id', sa.Integer(), primary_key=True), sa.Column('generation', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False), sa.Column('finished_at', sa.DateTime(timezone=True)),
        sa.Column('run_id', sa.Integer(), sa.ForeignKey('platform_sync_run.id', ondelete='SET NULL')),
        sa.Column('request', postgresql.JSONB(), nullable=False), sa.Column('request_hash', sa.String(64), nullable=False),
        sa.Column('snapshot_set_id', sa.String(64), nullable=False), sa.Column('snapshot_set', postgresql.JSONB(), nullable=False),
        sa.Column('response', postgresql.JSONB()), sa.Column('verdict', sa.String(16), nullable=False),
        sa.Column('consistent', sa.Boolean(), nullable=False), sa.Column('warnings', postgresql.JSONB(), nullable=False),
        sa.Column('cache_source_id', sa.Integer()))
    for table, columns in [('radar_nettrace_snapshot', ['generation', 'snapshot_set_id']),
                           ('radar_nettrace_device', ['snapshot_id', 'device_id']),
                           ('radar_nettrace_evaluation', ['generation', 'request_hash', 'snapshot_set_id'])]:
        for column in columns:
            op.create_index(f'ix_{table}_{column}', table, [column])


def downgrade():
    for table in ('radar_nettrace_evaluation', 'radar_nettrace_device', 'radar_nettrace_snapshot', 'radar_nettrace_config'):
        op.drop_table(table)
