"""Additive upgrade preserves existing images and findings; no guessed legacy kind."""
from alembic import command
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text

from tests.findings.test_migration_siem import scratch  # noqa: F401


def test_harbor_policy_migration_preserves_rows(scratch):  # noqa: F811
    engine, cfg = scratch
    before, after = 'f2d9a1c8b640', 'a63d1e7c9b20'
    assert ScriptDirectory.from_config(cfg).get_heads() == [after]
    command.upgrade(cfg, before)
    with engine.begin() as conn:
        conn.execute(text("""INSERT INTO vm_image
            (id, project, repository, digest, tags, scan_status, trivy_critical, trivy_high,
             trivy_medium, trivy_low, trivy_unknown, trivy_total, cves_scored, synced_at)
            VALUES (42, 'k8s', 'cilium', 'sha256:example', '["1.20.1"]', 'none', 0, 0, 0, 0, 0, 0, 0, now())"""))
        conn.execute(text("""INSERT INTO vm_image_cve
            (image_id, cve_id, package, installed_version, trivy_severity)
            VALUES (42, 'CVE-2026-1111', 'lib', '1', 'high')"""))
    command.upgrade(cfg, after)
    with engine.connect() as conn:
        row = conn.execute(text('SELECT id, repository, tags, artifact_kind, report_complete, is_index FROM vm_image LIMIT 2')).one()
        assert tuple(row) == (42, 'cilium', '["1.20.1"]', 'unknown', False, False)
        assert conn.scalar(text('SELECT count(*) FROM vm_image_cve')) == 1
        assert conn.scalar(text('SELECT count(*) FROM vm_harbor_project_policy')) == 0
    command.downgrade(cfg, before)
    assert 'vm_harbor_project_policy' not in inspect(engine).get_table_names()
    with engine.connect() as conn:
        assert conn.scalar(text('SELECT count(*) FROM vm_image')) == 1
        assert conn.scalar(text('SELECT count(*) FROM vm_image_cve')) == 1
