import json

import pytest
from fastapi.testclient import TestClient
from stools_threat_collector.app import create_app
from stools_threat_collector.storage import Store

POLICY = dict(collector_changes_days=30, successful_jobs_days=30, failed_jobs_days=90, source_runs_days=90)


def populated(tmp_path):
    store = Store(tmp_path / 'collector.db')
    source = store.save_source({'name': 'Test', 'publisher_id': 'test', 'url': 'https://example.org/rss'})
    store.ingest(source['id'], [{'external_id': 'a', 'url': 'https://example.org/a', 'title': 'Before', 'text': 'Before'}], {})
    with store.connection() as db:
        db.execute("UPDATE changes SET observed_at='2020-01-01T00:00:00+00:00'")
    return store, source


def test_retention_durable_floor_and_fresh_snapshot(tmp_path):
    store, source = populated(tmp_path)
    result = store.retention(POLICY, execute=False)
    assert next(i for i in result['items'] if i['id'] == 'collector_changes')['eligible_rows'] == 2
    assert len(store.changes(0)['events']) == 2
    store.retention(POLICY, execute=True)
    store = Store(store.path)
    assert store.info()['cursor_floor'] == store.info()['last_seq'] == 2
    with pytest.raises(ValueError, match='full sync'):
        store.changes(0)
    snapshot = store.create_snapshot()
    page = store.snapshot_page(snapshot['snapshot_id'])
    assert [e['entity_type'] for e in page['events']] == ['source', 'publication']
    assert page['baseline_seq'] == 2
    store.ingest(source['id'], [{'external_id': 'a', 'url': 'https://example.org/a', 'title': 'After', 'text': 'After'}], {})
    assert store.changes(2)['events'][0]['seq'] == 3


def test_snapshot_is_frozen_across_pages_and_pins_delta(tmp_path):
    store, source = populated(tmp_path)
    snapshot = store.create_snapshot()
    first = store.snapshot_page(snapshot['snapshot_id'], limit=1)
    store.ingest(source['id'], [{'external_id': 'a', 'url': 'https://example.org/a', 'title': 'After', 'text': 'After'}], {})
    with store.connection() as db:
        db.execute("UPDATE changes SET observed_at='2020-01-01T00:00:00+00:00'")
    store.retention(POLICY, execute=True)
    second = store.snapshot_page(snapshot['snapshot_id'], after=first['next_cursor'])
    assert second['events'][0]['payload']['title'] == 'Before'
    assert store.changes(snapshot['baseline_seq'])['events'][0]['payload']['title'] == 'After'
    assert store.info()['cursor_floor'] == snapshot['baseline_seq']


def test_retention_protects_pending_work_and_active_runs(tmp_path):
    store, source = populated(tmp_path)
    with store.connection() as db:
        for state in ('running', 'done', 'failed'):
            db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?)', (state, source['id'], state, '2020-01-01', '2020-01-02', None))
        for state in ('queued', 'running', 'succeeded', 'partial', 'failed', 'cancelled'):
            db.execute('INSERT INTO source_runs VALUES(?,?,?)', (state, source['id'], json.dumps(dict(state=state, finished_at='2020-01-02'))))
        db.execute("INSERT INTO pending_work VALUES('pending','enrichment','{}',NULL)")
    store.retention(POLICY, execute=True)
    with store.connection() as db:
        assert [r[0] for r in db.execute('SELECT id FROM jobs LIMIT 10')] == ['running']
        assert {r[0] for r in db.execute('SELECT id FROM source_runs LIMIT 10')} == {'queued', 'running'}
        assert db.execute('SELECT count(*) FROM publications').fetchone()[0] == 1
        assert db.execute('SELECT count(*) FROM pending_work').fetchone()[0] == 1


def test_retention_and_snapshot_api_auth_and_bounds(tmp_path):
    store, _ = populated(tmp_path)
    reader = {'Authorization': 'Bearer ' + store.create_token('reader', ['data:read'])}
    writer = {'Authorization': 'Bearer ' + store.create_token('writer', ['data:read', 'sources:write'])}
    with TestClient(create_app(store, run_scheduler=False)) as client:
        assert client.post('/api/v1/retention/run', json=POLICY).status_code == 401
        assert client.post('/api/v1/retention/run', json=POLICY, headers=reader).status_code == 403
        assert client.post('/api/v1/retention/preview', json={**POLICY, 'collector_changes_days': 0}, headers=writer).status_code == 422
        assert client.post('/api/v1/retention/preview', json=POLICY, headers=writer).status_code == 200
        assert client.post('/api/v1/snapshots').status_code == 401
        snapshot = client.post('/api/v1/snapshots', headers=reader).json()
        path = '/api/v1/snapshots/' + snapshot['snapshot_id']
        assert client.get(path + '?limit=501', headers=reader).status_code == 422
        assert client.get(path + '?after=100', headers=reader).status_code == 409
        assert client.get(path, headers=reader).status_code == 200


def test_offline_export_after_retention_is_explicit_snapshot_format(tmp_path):
    import zipfile
    from stools_threat_collector.bundle import export_bundle
    store, source = populated(tmp_path)
    store.retention(POLICY, execute=True)
    archive = tmp_path / 'snapshot.zip'
    export_bundle(store, 0, archive)
    with zipfile.ZipFile(archive) as z:
        manifest = json.loads(z.read('manifest.json'))
        assert manifest['format'] == 'snapshot-v1'
        assert manifest['protocol_version'] == 3  # Old clients must reject, not silently misread cursors.
        assert manifest['baseline_seq'] == 2
