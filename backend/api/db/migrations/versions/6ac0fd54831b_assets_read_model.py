"""Rebuildable Assets list index and transactional source invalidation."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "6ac0fd54831b"
down_revision = "5fb9ec43720a"
branch_labels = None
depends_on = None

SOURCES = ("asset", "asset_observation", "network", "asset_zone", "asset_settings")


def upgrade():
    op.create_table("platform_data_revision", sa.Column("module", sa.String(32), primary_key=True),
                    sa.Column("revision", sa.BigInteger(), nullable=False),
                    sa.Column("writer_xid", sa.BigInteger(), nullable=True))
    op.create_table("asset_read_state", sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("generation", sa.String(32), nullable=False), sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False), sa.Column("calculated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False))
    op.create_table("asset_read_dirty", sa.Column("asset_id", sa.Integer(), primary_key=True, autoincrement=False))
    op.create_table("asset_read_entry",
        sa.Column("generation", sa.String(32), primary_key=True),
        sa.Column("asset_id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("sort_name", sa.Text(collation="C"), nullable=False),
        sa.Column("sort_ip", sa.Text(collation="C"), nullable=False), sa.Column("network_id", sa.Integer()),
        *[sa.Column(k, sa.Text(), nullable=False) for k in ("zone", "placement", "criticality")],
        sa.Column("cluster", sa.Text()), sa.Column("laps", sa.Boolean()),
        *[sa.Column(k, pg.ARRAY(sa.Text()), nullable=False) for k in ("sources", "ad_keys", "tags", "search_terms")],
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False))
    op.create_table("asset_read_finding",
        sa.Column("generation", sa.String(32), primary_key=True),
        sa.Column("asset_id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("ordinal", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("key", sa.String(400), nullable=False), sa.Column("code", sa.String(32), nullable=False),
        sa.Column("payload", pg.JSONB(), nullable=False))
    op.execute("INSERT INTO platform_data_revision(module, revision) VALUES ('assets', 0)")
    # BEFORE statement: consistent revision -> business rows -> derived rows lock order.
    op.execute("""CREATE FUNCTION assets_revision_changed() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      INSERT INTO platform_data_revision(module, revision, writer_xid) VALUES ('assets', 1, txid_current())
      ON CONFLICT (module) DO UPDATE SET revision = platform_data_revision.revision + 1,
        writer_xid = EXCLUDED.writer_xid
      WHERE platform_data_revision.writer_xid IS DISTINCT FROM EXCLUDED.writer_xid;
      IF TG_TABLE_NAME NOT IN ('asset', 'asset_observation') OR TG_OP = 'TRUNCATE' THEN
        INSERT INTO asset_read_dirty(asset_id) VALUES (0) ON CONFLICT DO NOTHING;
      END IF;
      RETURN NULL;
    END $$""")
    op.execute("""CREATE FUNCTION assets_mark_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP <> 'INSERT' THEN
        IF TG_TABLE_NAME = 'asset' THEN
          INSERT INTO asset_read_dirty VALUES (OLD.id) ON CONFLICT DO NOTHING;
        ELSE
          INSERT INTO asset_read_dirty VALUES (OLD.asset_id) ON CONFLICT DO NOTHING;
        END IF;
      END IF;
      IF TG_OP <> 'DELETE' THEN
        IF TG_TABLE_NAME = 'asset' THEN
          INSERT INTO asset_read_dirty VALUES (NEW.id) ON CONFLICT DO NOTHING;
        ELSE
          INSERT INTO asset_read_dirty VALUES (NEW.asset_id) ON CONFLICT DO NOTHING;
        END IF;
      END IF;
      RETURN NULL;
    END $$""")
    for table in SOURCES:
        op.execute(f"CREATE TRIGGER assets_revision BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON {table} "
                   "FOR EACH STATEMENT EXECUTE FUNCTION assets_revision_changed()")
    for table in ("asset", "asset_observation"):
        op.execute(f"CREATE TRIGGER assets_dirty AFTER INSERT OR UPDATE OR DELETE ON {table} "
                   "FOR EACH ROW EXECUTE FUNCTION assets_mark_dirty()")


def downgrade():
    for table in ("asset", "asset_observation"):
        op.execute(f"DROP TRIGGER assets_dirty ON {table}")
    for table in SOURCES:
        op.execute(f"DROP TRIGGER assets_revision ON {table}")
    op.execute("DROP FUNCTION assets_mark_dirty()")
    op.execute("DROP FUNCTION assets_revision_changed()")
    for table in ("asset_read_finding", "asset_read_entry", "asset_read_dirty", "asset_read_state", "platform_data_revision"):
        op.drop_table(table)
