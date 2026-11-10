"""Offline threat intelligence reference materials, separate from executable hunts."""
import sqlalchemy as sa
from alembic import op

revision = 'f2d9a1c8b640'
down_revision = 'e85a3b9d2c71'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('th_intel_import',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_by', sa.String(255), nullable=False),
        sa.Column('result_json', sa.Text(), nullable=False),
        sa.Column('manifest_json', sa.Text(), nullable=False))
    op.create_index('ix_th_intel_import_created_at', 'th_intel_import', ['created_at'])
    op.create_table('th_intel_item',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('source_id', sa.String(100), nullable=False),
        sa.Column('external_id', sa.String(1024), nullable=False),
        sa.Column('kind', sa.String(16), nullable=False),
        sa.Column('title', sa.String(2000), nullable=False),
        sa.Column('url', sa.String(2048), nullable=False),
        sa.Column('text', sa.Text(), nullable=False),
        sa.Column('format', sa.String(32), nullable=False),
        sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('technique_ids_json', sa.Text(), nullable=False),
        sa.Column('full_text', sa.Boolean(), nullable=False),
        sa.Column('import_id', sa.String(64), sa.ForeignKey('th_intel_import.id'), nullable=False),
        sa.Column('content_hash', sa.String(64), nullable=False))
    for column in ('source_id', 'kind', 'collected_at'):
        op.create_index('ix_th_intel_item_'+column, 'th_intel_item', [column])



def downgrade():
    op.drop_table('th_intel_item')
    op.drop_table('th_intel_import')
