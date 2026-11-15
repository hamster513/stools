"""Track diagnostic datasets imported into the ordinary modules."""
import sqlalchemy as sa
from alembic import op

revision = "3df7ca2150e9"
down_revision = "2ce6b9a104f8"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "platform_diagnostic_import",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", sa.Text(), nullable=False),
        sa.Column("records_json", sa.Text(), nullable=False),
    )


def downgrade():
    op.drop_table("platform_diagnostic_import")
