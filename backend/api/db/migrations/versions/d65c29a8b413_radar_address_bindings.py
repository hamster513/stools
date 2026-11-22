"""Explicit nginx server address bindings for path correlation."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = 'd65c29a8b413'
down_revision = 'c54b18f7a302'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('radar_address_binding',
        sa.Column('server_id', sa.Integer(), sa.ForeignKey('radar_server.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('addresses', postgresql.JSONB(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False))


def downgrade():
    op.drop_table('radar_address_binding')
