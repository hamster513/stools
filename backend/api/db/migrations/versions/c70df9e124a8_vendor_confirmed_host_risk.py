"""Project vendor-confirmed SBOM CVEs onto the current risk hosts."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "c70df9e124a8"
down_revision = "d65c29a8b413"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("vm_host_sbom_scan", sa.Column("vendor_summary", JSONB()))
    op.create_table(
        "vm_sbom_confirmed_cve",
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("asset.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("cve_id", sa.String(32), sa.ForeignKey("vm_cve.cve_id"), primary_key=True),
        sa.Column("risk_raw", sa.Float(), nullable=False),
        sa.Column("risk", sa.Integer(), nullable=False),
    )
    op.create_index("ix_vm_sbom_confirmed_cve_cve_id", "vm_sbom_confirmed_cve", ["cve_id"])
    # Resolve by the exact, live source key. MaxPatrol replaces all its host IDs on import.
    op.execute("""
        CREATE VIEW vm_sbom_risk_host AS
        SELECT a.id AS asset_id, coalesce(h.id, -a.id) AS id,
               coalesce(h.hostname, nullif(a.fqdn,''), nullif(a.name,''), nullif(a.ip,''), a.id::text) AS hostname,
               coalesce(h.ip, a.ip) AS ip, coalesce(h.os_name, a.os) AS os_name,
               coalesce(h.groups, '') AS groups, coalesce(h.criticality, a.criticality) AS criticality,
               coalesce(h.zone, n.zone, '') AS zone
        FROM (SELECT DISTINCT asset_id FROM vm_sbom_confirmed_cve) e
        JOIN asset a ON a.id = e.asset_id AND a.merged_into IS NULL
        LEFT JOIN network n ON n.id = a.network_id
        LEFT JOIN LATERAL (
            SELECT v.id, v.hostname, v.ip, v.os_name, v.groups, v.criticality, v.zone
            FROM asset_observation o JOIN vm_host v ON v.hostname || '|' || v.ip = o.source_key
            WHERE o.asset_id = a.id AND o.source = 'vm' AND o.gone_at IS NULL
            ORDER BY v.hostname, v.ip LIMIT 1
        ) h ON true
    """)
    op.execute("""
        CREATE VIEW vm_risk_host AS
        SELECT id, hostname, ip, os_name, groups, criticality, zone, hostname AS state_hostname, internet FROM vm_host
        UNION ALL
        SELECT h.id, h.hostname, h.ip, h.os_name, h.groups, h.criticality, h.zone,
               'asset:' || h.asset_id::text AS state_hostname, coalesce(z.internet_access, false)
        FROM vm_sbom_risk_host h LEFT JOIN vm_zone z ON z.name = h.zone WHERE h.id < 0
    """)
    op.execute("""
        CREATE VIEW vm_risk_host_cve AS
        SELECT host_id, cve_id, risk_raw, risk, NULL::integer AS sbom_asset_id FROM vm_host_cve
        UNION ALL
        SELECT h.id, e.cve_id, e.risk_raw, e.risk, e.asset_id
        FROM vm_sbom_confirmed_cve e JOIN vm_sbom_risk_host h ON h.asset_id = e.asset_id
        WHERE NOT EXISTS (
            SELECT 1 FROM asset_observation o
            JOIN vm_host v ON v.hostname || '|' || v.ip = o.source_key
            JOIN vm_host_cve mp ON mp.host_id = v.id AND mp.cve_id = e.cve_id
            WHERE o.asset_id = e.asset_id AND o.source = 'vm' AND o.gone_at IS NULL
        )
    """)
    # A moved/disappeared source cannot attest to the old asset during the next scan.
    op.execute("""
        CREATE FUNCTION withdraw_unlinked_sbom_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF EXISTS (SELECT 1 FROM vm_sbom_confirmed_cve WHERE asset_id = OLD.asset_id) THEN
                DELETE FROM vm_sbom_confirmed_cve WHERE asset_id = OLD.asset_id;
            END IF;
            RETURN NULL;
        END $$;
    """)
    op.execute("""
        CREATE TRIGGER withdraw_sbom_on_move AFTER UPDATE OF asset_id, source, source_key, gone_at ON asset_observation
        FOR EACH ROW WHEN (OLD.source IN ('vm','ksc') AND OLD.gone_at IS NULL AND
            (OLD.asset_id, OLD.source, OLD.source_key, OLD.gone_at) IS DISTINCT FROM
            (NEW.asset_id, NEW.source, NEW.source_key, NEW.gone_at))
        EXECUTE FUNCTION withdraw_unlinked_sbom_evidence()
    """)
    op.execute("""
        CREATE TRIGGER withdraw_sbom_on_delete AFTER DELETE ON asset_observation
        FOR EACH ROW WHEN (OLD.source IN ('vm','ksc') AND OLD.gone_at IS NULL)
        EXECUTE FUNCTION withdraw_unlinked_sbom_evidence()
    """)
    # Serialize selective CVE pruning with MaxPatrol snapshot replacement and other publishers.
    # BEFORE STATEMENT also protects evidence removed by an asset FK cascade.
    op.execute("""
        CREATE FUNCTION lock_sbom_withdrawal() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            PERFORM pg_advisory_xact_lock(hashtext('vm_cve_membership'));
            RETURN NULL;
        END $$;
    """)
    op.execute("""
        CREATE TRIGGER lock_sbom_withdrawal BEFORE DELETE ON vm_sbom_confirmed_cve
        FOR EACH STATEMENT EXECUTE FUNCTION lock_sbom_withdrawal()
    """)
    # Cascaded withdrawals (including asset deletion) must also expire aggregate caches.
    op.execute("""
        CREATE FUNCTION invalidate_sbom_risk_cache() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF EXISTS (SELECT 1 FROM changed) THEN
                IF TG_OP = 'DELETE' THEN
                    DELETE FROM vm_cve c WHERE c.cve_id IN (SELECT cve_id FROM changed)
                        AND NOT EXISTS (SELECT 1 FROM vm_host_cve m WHERE m.cve_id = c.cve_id)
                        AND NOT EXISTS (SELECT 1 FROM vm_image_cve i WHERE i.cve_id = c.cve_id)
                        AND NOT EXISTS (SELECT 1 FROM vm_sbom_confirmed_cve s WHERE s.cve_id = c.cve_id);
                END IF;
                INSERT INTO app_setting (key, value_json, updated_at)
                    VALUES ('vm.attack_layer','{}',now()), ('vm.stats','{}',now())
                    ON CONFLICT (key) DO UPDATE SET value_json = '{}', updated_at = now();
            END IF;
            RETURN NULL;
        END $$;
    """)
    for event, rows in (("INSERT", "NEW"), ("UPDATE", "NEW"), ("DELETE", "OLD")):
        op.execute(f"""
            CREATE TRIGGER invalidate_sbom_risk_on_{event.lower()} AFTER {event} ON vm_sbom_confirmed_cve
            REFERENCING {rows} TABLE AS changed FOR EACH STATEMENT EXECUTE FUNCTION invalidate_sbom_risk_cache()
        """)


def downgrade():
    op.execute("DROP TRIGGER withdraw_sbom_on_move ON asset_observation")
    op.execute("DROP TRIGGER withdraw_sbom_on_delete ON asset_observation")
    op.execute("DROP FUNCTION withdraw_unlinked_sbom_evidence()")
    op.execute("DROP VIEW vm_risk_host_cve, vm_risk_host")
    op.execute("DROP VIEW vm_sbom_risk_host")
    op.drop_table("vm_sbom_confirmed_cve")
    op.execute("DROP FUNCTION lock_sbom_withdrawal()")
    op.execute("DROP FUNCTION invalidate_sbom_risk_cache()")
    op.drop_column("vm_host_sbom_scan", "vendor_summary")
