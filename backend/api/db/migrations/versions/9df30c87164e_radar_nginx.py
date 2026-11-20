"""Radar nginx inventory and encrypted configuration snapshots."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = '9df30c87164e'
down_revision = '8ce2bf76053d'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('radar_server',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('hostname', sa.String(255), nullable=False, unique=True),
        sa.Column('latest_snapshot_id', sa.Integer(), nullable=True),
        sa.Column('search_text', sa.Text(), nullable=False))
    op.create_table('radar_snapshot',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('server_id', sa.Integer(), sa.ForeignKey('radar_server.id', ondelete='CASCADE'), nullable=False),
        sa.Column('imported_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('filename', sa.String(255), nullable=False),
        sa.Column('sha256', sa.String(64), nullable=False),
        sa.Column('original_encrypted', sa.Text(), nullable=False),
        sa.Column('document', postgresql.JSONB(), nullable=False))
    op.create_index('ix_radar_snapshot_server_id', 'radar_snapshot', ['server_id'])


def downgrade():
    op.drop_table('radar_snapshot')
    op.drop_table('radar_server')
