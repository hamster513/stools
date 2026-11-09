"""Monitoring enrichment, PoC and durable local analyst decisions."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = 'c83f0e4a921d'
down_revision = 'b76d23a04ef1'
branch_labels = None
depends_on = None


def upgrade():
    for name in ('vm_trend_enrichment', 'vm_trend_poc'):
        op.create_table(name,
            sa.Column('generation', sa.String(36), primary_key=True),
            sa.Column('external_id', sa.String(100), primary_key=True),
            sa.Column('revision', sa.Integer(), nullable=False),
            sa.Column('data', postgresql.JSONB(), nullable=False),
            sa.Column('retracted', sa.Boolean(), nullable=False))
    op.create_table('vm_trend_poc_review',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('candidate_id', sa.String(100), nullable=False),
        sa.Column('commit_sha', sa.String(64), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('actor', sa.String(255), nullable=False),
        sa.Column('state', sa.String(20), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('evidence', postgresql.JSONB(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('candidate_id', 'commit_sha', 'version', name='uq_trend_poc_review_version'))
    op.create_index('ix_vm_trend_poc_review_candidate_id', 'vm_trend_poc_review', ['candidate_id'])
    op.create_table('vm_trend_policy',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('scope', sa.String(32), nullable=False),
        sa.Column('target_key', sa.String(2000), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('actor', sa.String(255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('history', postgresql.JSONB(), nullable=False))


def downgrade():
    for name in ('vm_trend_policy', 'vm_trend_poc_review', 'vm_trend_poc', 'vm_trend_enrichment'):
        op.drop_table(name)
