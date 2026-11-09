"""Имена, описания и полный PDQL запросов хантов.

Revision ID: d74f2a8c1e90
Revises: c83f0e4a921d
"""
import sqlalchemy as sa
from alembic import op

revision = "d74f2a8c1e90"
down_revision = "c83f0e4a921d"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("th_query", sa.Column("name", sa.String(255), nullable=False, server_default=""))
    op.add_column("th_query", sa.Column("description", sa.Text(), nullable=False, server_default=""))
    op.add_column("th_query", sa.Column("is_full_pdql", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("th_deep_hunt", sa.Column("is_full_pdql", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.execute("UPDATE th_query SET name = query_id WHERE name = ''")


def downgrade():
    op.drop_column("th_deep_hunt", "is_full_pdql")
    op.drop_column("th_query", "is_full_pdql")
    op.drop_column("th_query", "description")
    op.drop_column("th_query", "name")
