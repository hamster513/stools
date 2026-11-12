"""Последние авторизации из табличных списков SIEM."""
import sqlalchemy as sa
from alembic import op

revision = 'd96b4e0c132f'
down_revision = 'c85a3d9b021e'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('siem_logon',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('key', sa.String(64), nullable=False, unique=True),
        sa.Column('scope', sa.String(64), nullable=False),
        *[sa.Column(n, sa.String(255), nullable=False) for n in
          ('table_name', 'user', 'domain', 'src_host', 'dst_host')],
        *[sa.Column(n, sa.String(64), nullable=False) for n in ('src_ip', 'dst_ip')],
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=False),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('asset_user.id', ondelete='SET NULL')),
        sa.Column('src_asset_id', sa.Integer(), sa.ForeignKey('asset.id', ondelete='SET NULL')),
        sa.Column('dst_asset_id', sa.Integer(), sa.ForeignKey('asset.id', ondelete='SET NULL')),
    )
    for name in ('scope', 'last_login', 'user_id', 'src_asset_id', 'dst_asset_id'):
        op.create_index(f'ix_siem_logon_{name}', 'siem_logon', [name])
    op.create_table('siem_logon_job',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('kind', sa.String(32), nullable=False),
        sa.Column('stage', sa.String(32), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('progress', sa.Integer(), nullable=False),
        sa.Column('processed', sa.Integer(), nullable=False),
        sa.Column('total', sa.Integer()),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('error', sa.Text()),
        sa.Column('cancel_requested', sa.Boolean(), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('finished_at', sa.DateTime(timezone=True)),
        sa.Column('started_by', sa.String(255), nullable=False),
    )
    for name in ('kind', 'status'):
        op.create_index(f'ix_siem_logon_job_{name}', 'siem_logon_job', [name])


def downgrade():
    op.drop_table('siem_logon_job')
    op.drop_table('siem_logon')
