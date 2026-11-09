"""Persist paid translations and explanations independently of collector generations."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'e85a3b9d2c71'
down_revision = 'd74f2a8c1e90'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('vm_trend_ai_answer',
        sa.Column('cache_key', sa.String(64), primary_key=True),
        sa.Column('target', sa.String(140), nullable=False),
        sa.Column('mode', sa.String(16), nullable=False),
        sa.Column('answer', postgresql.JSONB(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))
    op.create_index('ix_vm_trend_ai_answer_target_mode_created', 'vm_trend_ai_answer', ['target', 'mode', 'created_at'])


def downgrade():
    op.drop_table('vm_trend_ai_answer')
