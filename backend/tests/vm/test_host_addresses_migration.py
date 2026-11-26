"""The address column preserves the old export and has a safe empty default."""
from alembic import command
from sqlalchemy import inspect, text

from tests.findings.test_migration_siem import scratch  # noqa: F401


def test_host_addresses_upgrade_and_downgrade_preserve_coverage(scratch):  # noqa: F811
    engine, cfg = scratch
    before, after = 'c70df9e124a8', 'd81e0af235b9'
    command.upgrade(cfg, before)
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO vm_host_cve_coverage (source_key, observed_at) VALUES ('old.example.test|192.0.2.10', '2026-01-01T00:00:00Z')"))
    for target in (after, before, after):
        if target == before:
            command.downgrade(cfg, target)
        else:
            command.upgrade(cfg, target)
        assert ('ips' in {c['name'] for c in inspect(engine).get_columns('vm_host_cve_coverage')}) == (target == after)
        with engine.connect() as conn:
            assert conn.scalar(text('SELECT source_key FROM vm_host_cve_coverage LIMIT 2')) == 'old.example.test|192.0.2.10'
            if target == after:
                assert conn.scalar(text('SELECT ips FROM vm_host_cve_coverage LIMIT 2')) == []
