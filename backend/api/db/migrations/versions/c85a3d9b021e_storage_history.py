"""Storage measurements and daily schedule."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = 'c85a3d9b021e'
down_revision = 'b74f2c8a910d'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('platform_storage_sample', sa.Column('id', sa.Integer(), primary_key=True),
                    sa.Column('measured_at', sa.DateTime(timezone=True), nullable=False),
                    sa.Column('data', postgresql.JSONB(), nullable=False))
    op.create_index('ix_platform_storage_sample_measured_at', 'platform_storage_sample', ['measured_at'])
    op.execute("""INSERT INTO platform_schedule(module,kind,target_id,interval_hours,weekdays,run_time,enabled,next_run_at)
        VALUES ('platform','storage',0,24,'0123456','03:00',true,now())
        ON CONFLICT (module,kind,target_id) DO NOTHING""")


def downgrade():
    op.execute("DELETE FROM platform_schedule WHERE module='platform' AND kind='storage' AND target_id=0")
    op.drop_table('platform_storage_sample')
