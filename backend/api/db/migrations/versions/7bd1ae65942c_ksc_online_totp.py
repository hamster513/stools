"""Encrypted TOTP secret for unattended KSC connections."""
import sqlalchemy as sa
from alembic import op

revision = "7bd1ae65942c"
down_revision = "6ac0fd54831b"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("ksc_connection", sa.Column("totp_secret", sa.Text(), nullable=False, server_default=""))


def downgrade():
    op.drop_column("ksc_connection", "totp_secret")
