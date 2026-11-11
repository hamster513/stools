"""Artifact kind and effective Harbor vulnerability pull policy."""
import sqlalchemy as sa
from alembic import op

revision = 'a63d1e7c9b20'
down_revision = 'f2d9a1c8b640'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('vm_image', sa.Column('artifact_kind', sa.String(16), nullable=False, server_default='unknown'))
    op.add_column('vm_image', sa.Column('is_index', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column('vm_image', sa.Column('report_complete', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_table('vm_harbor_project_policy',
        sa.Column('project', sa.String(255), primary_key=True),
        sa.Column('registry_url', sa.String(512), nullable=False),
        sa.Column('data', sa.JSON(), nullable=False),
        sa.Column('checked_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('error', sa.String(255), nullable=False))


def downgrade():
    op.drop_table('vm_harbor_project_policy')
    for column in ('report_complete', 'is_index', 'artifact_kind'):
        op.drop_column('vm_image', column)
