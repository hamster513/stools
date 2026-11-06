import pytest
from sqlalchemy import func, select

from api.modules.vm.services.trends.ingest import apply_page
from api.modules.vm.trend_models import VmTrendIngestState, VmTrendPublication


def page():
    return {'protocol_version': 1, 'collector_id': 'collector-1', 'epoch': 'epoch-1', 'until_seq': 2,
        'next_cursor': 2, 'has_more': False, 'events': [
            {'seq': 1, 'entity_type': 'source', 'operation': 'upsert', 'entity_id': 'source-1', 'revision': 1,
             'observed_at': '2026-11-05T12:00:00Z', 'payload': {'id': 'source-1', 'name': 'Test', 'publisher_id': 'test', 'adapter': 'kev'}},
            {'seq': 2, 'entity_type': 'publication', 'operation': 'upsert', 'entity_id': 'pub-1', 'revision': 1,
             'observed_at': '2026-11-05T12:00:00Z', 'payload': {'source_id': 'source-1', 'external_id': 'article-1',
                 'title': 'CVE-2026-12345', 'text': 'Confirmed exploitation', 'identifiers': ['CVE-2026-12345'],
                 'url': 'https://example.test/a', 'publisher_id': 'test', 'published_at': '2026-11-05T10:00:00Z',
                 'evidence_kind': 'kev', 'exploitation_confirmed': True}}]}


def test_page_and_cursor_atomic_idempotent(db_session):
    apply_page(db_session, page())
    apply_page(db_session, page())
    assert db_session.scalar(select(func.count()).select_from(VmTrendPublication)) == 1
    assert db_session.get(VmTrendIngestState, 1).cursor == 2


def test_gap_and_changed_epoch_require_recovery(db_session):
    broken = page()
    broken['events'][0]['seq'] = 3
    with pytest.raises(ValueError):
        apply_page(db_session, broken)
    db_session.rollback()
    apply_page(db_session, page())
    different = {**page(), 'epoch': 'epoch-2'}
    with pytest.raises(ValueError, match='полная'):
        apply_page(db_session, different)


def test_complete_generation_only_publishes_after_analysis(db_session):
    from api.modules.vm.services.trends.analyze import process_pending
    payload = page()
    first = {**payload, 'events': payload['events'][:1], 'next_cursor': 1, 'has_more': True}
    apply_page(db_session, first)
    process_pending(db_session)
    assert db_session.get(VmTrendIngestState, 1).active_generation is None
    apply_page(db_session, {**payload, 'events': payload['events'][1:]})
    assert db_session.get(VmTrendIngestState, 1).active_generation is None
    process_pending(db_session)
    state = db_session.get(VmTrendIngestState, 1)
    assert state.active_generation == state.generation


def test_archive_hash_and_replay(db_session):
    import hashlib
    import io
    import json
    import zipfile

    from api.modules.vm.services.trends.bundle import import_bundle
    payload = page()
    body = (json.dumps(payload)+'\n').encode()
    manifest = {key: payload[key] for key in ('protocol_version', 'collector_id', 'epoch', 'until_seq')}
    manifest.update(after=0, sha256=hashlib.sha256(body).hexdigest())
    def bundle(manifest):
        result = io.BytesIO()
        with zipfile.ZipFile(result, 'w') as archive:
            archive.writestr('manifest.json', json.dumps(manifest))
            archive.writestr('pages.jsonl', body)
        result.seek(0)
        return result
    with pytest.raises(ValueError, match='сумма'):
        import_bundle(db_session, bundle({**manifest, 'sha256': 'broken'}))
    assert db_session.get(VmTrendIngestState, 1) is None
    import_bundle(db_session, bundle(manifest))
    import_bundle(db_session, bundle(manifest))
    assert db_session.scalar(select(func.count()).select_from(VmTrendPublication)) == 1


def test_archive_full_reset_requires_complete_history(db_session):
    import hashlib
    import io
    import json
    import zipfile

    from api.modules.vm.services.trends.bundle import import_bundle
    apply_page(db_session, page())
    payload = {**page(), 'epoch': 'restored'}
    body = (json.dumps(payload)+'\n').encode()
    manifest = {key: payload[key] for key in ('protocol_version', 'collector_id', 'epoch', 'until_seq')}
    manifest.update(after=0, sha256=hashlib.sha256(body).hexdigest())
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.writestr('manifest.json', json.dumps(manifest))
        archive.writestr('pages.jsonl', body)
    stream.seek(0)
    import_bundle(db_session, stream, reset=True)
    assert db_session.get(VmTrendIngestState, 1).epoch == 'restored'


def test_empty_title_cannot_poison_delivery_log(db_session):
    data = page()
    data['events'][1]['payload']['title'] = ''
    apply_page(db_session, data)
    assert db_session.get(VmTrendIngestState, 1).cursor == 2
    assert db_session.scalar(select(VmTrendPublication)).data['title'] == 'https://example.test/a'


def test_old_package_replay_cannot_publish_incomplete_new_batch(db_session):
    from api.modules.vm.services.trends.analyze import process_pending
    data = page()
    apply_page(db_session, data)
    process_pending(db_session)
    extension = {**data['events'][0], 'seq': 3, 'revision': 2}
    apply_page(db_session, {**data, 'events': [extension], 'until_seq': 4, 'next_cursor': 3, 'has_more': True})
    apply_page(db_session, data)
    assert db_session.get(VmTrendIngestState, 1).batch_until == 4
