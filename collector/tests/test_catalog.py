import pytest
from stools_threat_collector.catalog import import_catalog
from stools_threat_collector.storage import Store


def test_catalog_upgrade_preserves_existing_source_and_checkpoint(tmp_path):
    store = Store(tmp_path / 'collector.db')
    original = store.save_source({'name': 'User title', 'publisher_id': 'owner',
                                 'url': 'https://example.org/feed', 'enabled': True, 'interval_minutes': 240})
    store.ingest(original['id'], [], {'etag': 'keep'})
    before = store.source(original['id'])
    rows = [{'name': 'Default title', 'publisher_id': 'example', 'url': original['url']},
            {'name': 'New feed', 'publisher_id': 'new', 'url': 'https://new.example/feed'}]
    assert import_catalog(store, rows) == 1
    assert store.source(original['id']) == before
    assert len(store.sources()) == 2
    cursor = store.info()['last_seq']
    assert import_catalog(store, rows) == 0
    assert store.info()['last_seq'] == cursor
    assert next(x for x in store.sources() if x['id'] != original['id'])['enabled'] is False


def test_invalid_catalog_is_validated_before_any_write(tmp_path):
    store = Store(tmp_path / 'collector.db')
    with pytest.raises(ValueError):
        import_catalog(store, [{'name': 'Valid', 'publisher_id': 'new', 'url': 'https://new.example/feed'},
                               {'name': 'Invalid', 'publisher_id': 'new', 'url': 'file:///tmp/feed'}])
    assert store.sources() == []


def test_duplicate_urls_do_not_create_duplicate_sources(tmp_path):
    store = Store(tmp_path / 'collector.db')
    row = {'name': 'Feed', 'publisher_id': 'new', 'url': 'https://new.example/feed'}
    assert import_catalog(store, [row, row]) == 1


def test_soc_catalog_every_row_has_mapping():
    import json
    from pathlib import Path
    import stools_threat_collector.catalog as catalog
    snapshot = json.loads((Path(__file__).parent / 'fixtures/soc_sources_2026_11_06.json').read_text())
    manifest = json.loads(Path(catalog.__file__).with_name('catalog_manifest.json').read_text())
    rows = manifest['rows']
    assert sorted(row['origin_index'] for row in rows) == list(range(len(snapshot)))
    assert all(row['action'] != 'pending_adapter' for row in rows)
    defaults = json.loads(Path(catalog.__file__).with_name('sources.json').read_text())
    assert {row['catalog_key'] for row in rows} <= {row['catalog_key'] for row in defaults}


def test_catalog_preserves_distinct_feeds_on_same_domain():
    from stools_threat_collector.catalog import build_catalog_plan
    rows = [{'name': 'Security', 'publisher_id': 'same', 'url': 'https://example.org/security'},
            {'name': 'IT', 'publisher_id': 'same', 'url': 'https://example.org/all'}]
    plan = build_catalog_plan([], rows)
    assert [r.action for r in plan.rows] == ['add', 'add']


def test_catalog_repeat_import_is_idempotent():
    from stools_threat_collector.catalog import build_catalog_plan
    rows = [{'name': 'Feed', 'publisher_id': 'owner', 'url': 'https://example.org/feed'}]
    plan = build_catalog_plan([], rows + rows)
    assert [r.action for r in plan.rows] == ['add', 'duplicate']
    assert build_catalog_plan([{**rows[0], 'id': 'existing'}], rows).rows[0].action == 'existing'


def test_catalog_operator_settings_win():
    from stools_threat_collector.catalog import build_catalog_plan
    old = {'id': 'stable', 'name': 'Mine', 'publisher_id': 'owner', 'url': 'https://example.org/feed', 'enabled': True, 'interval_minutes': 240, 'checkpoint': {'etag': 'keep'}}
    incoming = {'name': 'Shipped', 'publisher_id': 'owner', 'url': old['url'], 'interval_minutes': 60}
    row = build_catalog_plan([old], [incoming]).rows[0]
    assert row.existing_id == 'stable' and row.action == 'existing'
    assert row.selected is False and 'name' in row.changed_fields
    assert old['checkpoint'] == {'etag': 'keep'} and old['enabled']


def test_catalog_conflict_requires_selection():
    from stools_threat_collector.catalog import build_catalog_plan
    row = {'name': 'Feed', 'publisher_id': 'owner', 'url': 'https://example.org/feed'}
    existing = [{**row, 'id': 'a'}, {**row, 'id': 'b'}]
    item = build_catalog_plan(existing, [row]).rows[0]
    assert item.action == 'conflict' and not item.selected
    assert set(item.conflicting_ids) == {'a', 'b'}

def test_legacy_telegram_case_normalization_preserves_checkpoint(tmp_path):
    import json
    store = Store(tmp_path / 'collector.db')
    source = store.save_source({'name': 'Legacy channel', 'publisher_id': 'legacy',
        'url': 'https://t.me/SecLabNews', 'adapter': 'telegram', 'telegram_mode': 'mtproto'})
    with store.connection() as db:
        legacy = {**source, 'url': 'https://t.me/SecLabNews'}
        db.execute('UPDATE sources SET config=?,checkpoint=? WHERE id=?',
            (json.dumps(legacy), json.dumps({'last_id': 1234}), source['id']))
    store.save_source({**source, 'importance': 5}, source['id'])
    assert store.source(source['id'])['checkpoint'] == {'last_id': 1234}

def test_broad_it_feeds_do_not_default_to_security_news():
    import json
    from pathlib import Path
    import stools_threat_collector.catalog as catalog
    rows = json.loads(Path(catalog.__file__).with_name('sources.json').read_text())
    broad = {'InfoQ', 'Ars Technica', 'Inc Russia', 'Slashdot', 'Stack Overflow Blog',
             'Tproger', 'CNCF Blog', 'CNews Security', 'iXBT News', 'The Verge', 'Lobsters', 'Slashdot Developers'}
    assert {r['name'] for r in rows if r['name'] in broad and r['content_scope'] == 'general_it'} == broad
    assert next(r for r in rows if r['name'] == 'Lobsters Security')['content_scope'] == 'security_news'
