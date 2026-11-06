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
