import json
import sqlite3
import pytest
from stools_threat_collector.storage import Store


def context():
    return {'cve_id': 'CVE-2026-12345', 'cvss': 9.8, 'epss': None, 'known_exploited': None,
            'providers': {}, 'fetched_at': '2026-11-07T00:00:00Z'}


def test_v1_consumer_compatibility(tmp_path):
    store = Store(tmp_path / 'data.db')
    source = store.save_source({'name': 'Feed', 'publisher_id': 'example', 'url': 'https://example.org/feed'})
    store.save_monitoring('cve_enrichment', 'cve:CVE-2026-12345', context())
    assert store.info()['protocol_version'] == 1
    assert [event['entity_type'] for event in store.changes(0)['events']] == ['source']
    assert store.source(source['id'])['checkpoint'] == {}
    store.enable_protocol_v2()
    data = store.changes(0)
    assert data['protocol_version'] == 2
    assert [event['seq'] for event in data['events']] == [1, 2]
    assert data['events'][-1]['payload']['epss'] is None
    store.enable_protocol_v2()
    assert store.info()['last_seq'] == 2


def test_monitoring_revisions_are_idempotent(tmp_path):
    store = Store(tmp_path / 'data.db')
    store.enable_protocol_v2()
    assert store.save_monitoring('cve_enrichment', 'cve:CVE-2026-12345', context()) == 1
    assert store.save_monitoring('cve_enrichment', 'cve:CVE-2026-12345', context()) == 1
    assert store.info()['last_seq'] == 1
    updated = {**context(), 'cvss': 8.1}
    assert store.save_monitoring('cve_enrichment', 'cve:CVE-2026-12345', updated) == 2
    assert store.changes(0)['events'][-1]['revision'] == 2


def test_migration_keeps_legacy_telegram_configuration(tmp_path):
    path = tmp_path / 'data.db'
    store = Store(path)
    source = store.save_source({'name': 'TG', 'publisher_id': 'tg', 'adapter': 'telegram', 'url': 'https://t.me/example', 'enabled': True})
    with sqlite3.connect(path) as db:
        value = json.loads(db.execute('SELECT config FROM sources WHERE id=?', (source['id'],)).fetchone()[0])
        value.pop('telegram_mode', None)
        db.execute('UPDATE sources SET config=?, checkpoint=? WHERE id=?', (json.dumps(value), '{"last_id":42}', source['id']))
        db.execute("DELETE FROM meta WHERE key='monitoring_schema'")
    reopened = Store(path)
    assert reopened.source(source['id'])['telegram_mode'] == 'mtproto'
    assert reopened.source(source['id'])['enabled']
    assert reopened.source(source['id'])['checkpoint'] == {'last_id': 42}


def test_catalog_apply_is_atomic_and_checks_revision(tmp_path):
    from stools_threat_collector.catalog import build_catalog_plan, apply_catalog_plan
    store = Store(tmp_path / 'data.db')
    row = {'name': 'Feed', 'publisher_id': 'owner', 'url': 'https://example.org/feed'}
    plan = build_catalog_plan([], [row, {**row, 'url': 'file:///private/data'}])
    with pytest.raises(ValueError):
        apply_catalog_plan(store, plan, plan.expected_revision)
    assert store.sources() == []
    valid = build_catalog_plan([], [row])
    store.save_source({**row, 'url': 'https://changed.example.org/feed'})
    with pytest.raises(ValueError, match='revision'):
        apply_catalog_plan(store, valid, valid.expected_revision)
    assert len(store.sources()) == 1


def test_protocol_enable_drains_all_queued_batches(tmp_path, monkeypatch):
    import stools_threat_collector.storage as module
    monkeypatch.setattr(module, 'PUBLISH_BATCH_SIZE', 4000, raising=False)
    store = Store(tmp_path / 'data.db')
    with store.connection() as db:
        rows = []
        for number in range(10001):
            cve = f'CVE-2026-{12345 + number}'
            identity = 'cve:' + cve
            rows.append(('publish:' + identity, 'cve_enrichment', json.dumps({'id': identity, 'revision': 1, 'payload': {**context(), 'cve_id': cve}})))
        db.executemany('INSERT INTO pending_work(id,kind,data) VALUES(?,?,?)', rows)
    store.enable_protocol_v2()
    assert store.info()['last_seq'] == 10001

    with store.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM pending_work WHERE id LIKE 'publish:%'").fetchone()[0] == 0
