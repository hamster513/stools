"""A large KSC snapshot must not be scanned again for every software host."""
import datetime as dt

from sqlalchemy import insert, select, text

from api.modules.ksc.models import KscHost, KscServer, KscSnapshot
from tests.findings.test_migration_siem import scratch  # noqa: F401


def test_host_lookup_does_not_scan_the_entire_snapshot(db_session):
    db = db_session
    server = KscServer(name='Lookup performance')
    db.add(server); db.flush()
    snap = KscSnapshot(server_id=server.id, collected_at=dt.datetime.now(dt.UTC), source='file')
    db.add(snap); db.flush()
    db.execute(insert(KscHost), [{'snapshot_id': snap.id, 'host_id': f'host-{i}', 'name': f'Host {i}'} for i in range(5000)])
    # Repeated host IDs in different snapshots remain separate observations.
    second = KscSnapshot(server_id=server.id, collected_at=dt.datetime.now(dt.UTC), source='file')
    db.add(second); db.flush()
    db.add(KscHost(snapshot_id=second.id, host_id='host-4999', name='Other snapshot'))
    db.commit()
    db.execute(text('ANALYZE ksc_host'))
    query = select(KscHost.name).where(KscHost.snapshot_id == snap.id, KscHost.host_id == 'host-4999').limit(2)
    assert db.scalars(query).all() == ['Host 4999']
    sql = str(query.compile(db.get_bind(), compile_kwargs={'literal_binds': True}))
    plan = db.execute(text('EXPLAIN (ANALYZE, FORMAT JSON) '+sql)).scalar_one()[0]['Plan']

    def examined(node):
        own = (node.get('Actual Rows', 0) + node.get('Rows Removed by Filter', 0)) * node.get('Actual Loops', 0)
        return own + sum(examined(child) for child in node.get('Plans', []))

    assert examined(plan) < 50, 'Host lookup scans unrelated hosts in the same snapshot'


def test_host_lookup_index_migration_preserves_repeated_observations(scratch):  # noqa: F811
    from alembic import command
    from sqlalchemy import inspect

    engine, cfg = scratch
    before, after = '7bd1ae65942c', '8ce2bf76053d'
    command.upgrade(cfg, before)
    with engine.begin() as conn:
        server = conn.scalar(insert(KscServer).values(name='Index migration').returning(KscServer.id))
        snap = conn.scalar(insert(KscSnapshot).values(server_id=server, source='file', collected_at=dt.datetime.now(dt.UTC)).returning(KscSnapshot.id))
        conn.execute(insert(KscHost), [{'snapshot_id': snap, 'host_id': 'same', 'name': name} for name in ('First observation', 'Second observation')])
    for target in (after, before, after):
        if target == before:
            command.downgrade(cfg, target)
        else:
            command.upgrade(cfg, target)
        indexes = {item['name']: item for item in inspect(engine).get_indexes('ksc_host')}
        assert ('ix_ksc_host_snapshot_host' in indexes) == (target == after)
        if target == after:
            assert indexes['ix_ksc_host_snapshot_host']['column_names'] == ['snapshot_id', 'host_id']
            assert not indexes['ix_ksc_host_snapshot_host']['unique']
        with engine.connect() as conn:
            rows = conn.execute(select(KscHost.host_id, KscHost.name).order_by(KscHost.id).limit(3)).all()
            assert rows == [('same', 'First observation'), ('same', 'Second observation')]
