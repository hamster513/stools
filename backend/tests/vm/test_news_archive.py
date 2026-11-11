"""Offline ZIP news must enter VM's publication pipeline, without SIEM rights."""
import pytest
from sqlalchemy import func, select
from api.modules.siem.hunting.intel import import_bundle
from api.modules.siem.hunting.models import ThIntelImport, ThIntelItem
from api.modules.vm.services.trends.analyze import process_pending
from api.modules.vm.services.trends.ingest import apply_page
from api.modules.vm.trend_models import VmTrendIngestState, VmTrendPublication
from tests.siem_hunting.test_intel import bundle, item
from tests.vm.test_trend_sync import page

URL = '/api/vm/trends/news-archive'


def upload(client, data):
    return client.post(URL, files={'file': ('news.zip', data, 'application/zip')})


def listing(client, view='mentions'):
    response = client.get('/api/vm/trends', params={'view': view, 'period': 'all'})
    assert response.status_code == 200, response.text
    return response.json()


def test_vm_only_admin_imports_news_into_trends_and_repeats_safely(client_as, db_session):
    client = client_as({'vm': 'admin'})
    data = bundle([item(title='Security flaw CVE-2026-12345')])
    response = upload(client, data)
    assert response.status_code == 200, response.text
    assert response.json()['news_total'] == 1
    assert listing(client)['items'][0]['id'] == 'CVE-2026-12345'
    evidence = client.get('/api/vm/trends/CVE-2026-12345?period=all').json()['evidence'][0]
    assert evidence['url'] == item()['url']
    assert evidence['source_name'] == 'Test feed'
    assert evidence['text'] == item()['text']
    assert evidence['published_at'].startswith('2026-11-01')
    assert evidence['classification']['category'] == 'relevant'
    assert not evidence['exploitation_confirmed']
    assert upload(client, data).json()['duplicate']
    assert db_session.scalar(select(func.count()).select_from(VmTrendPublication)) == 1
    assert client.get(URL+'/imports').json()['items'][0]['added'] == 1


@pytest.mark.parametrize('role', ['read', 'write', 'deny'])
def test_archive_requires_vm_admin(client_as, role):
    assert upload(client_as({'vm': role, 'siem': 'admin'}), bundle()).status_code == 403


def test_old_archives_and_invalid_archives_do_not_replace_news(auth_client, db_session):
    assert upload(auth_client, bundle(date='2026-11-03T00:00:00Z')).status_code == 200
    old = bundle([item(text='Old text')], date='2026-11-01T00:00:00Z')
    assert upload(auth_client, old).json()['stale'] == 1
    assert upload(auth_client, bundle(manifest_change={'items_sha256': '0'*64})).status_code == 422
    assert db_session.scalar(select(func.count()).select_from(ThIntelImport)) == 2
    assert db_session.scalar(select(VmTrendPublication)).data['text'] == item()['text']


def test_legacy_news_backfill_and_collector_reset_preserve_publications(auth_client, db_session):
    import_bundle(db_session, bundle(), 'old-import')
    process_pending(db_session)
    assert listing(auth_client)['total'] == 1
    original = db_session.scalar(select(VmTrendPublication))
    key, revision = original.external_id, original.revision
    apply_page(db_session, page())
    process_pending(db_session)
    apply_page(db_session, {**page(), 'epoch': 'new-history'}, reset=True)
    process_pending(db_session)
    state = db_session.get(VmTrendIngestState, 1)
    rows = list(db_session.scalars(select(VmTrendPublication).where(VmTrendPublication.generation == state.active_generation)))
    assert len(rows) == 2
    archived = next(r for r in rows if r.external_id == key)
    assert archived.revision == revision
    assert db_session.scalar(select(func.count()).select_from(ThIntelItem)) == 1


def test_background_and_undated_news_remain_available_in_archive(auth_client):
    items = [item(external_id='noise', title='GeForce sale', text='New smartphone price', published_at=None)]
    assert upload(auth_client, bundle(items)).status_code == 200
    assert listing(auth_client)['total'] == 0
    assert listing(auth_client, 'archive')['total'] == 1


def test_rules_stay_reference_materials(auth_client, db_session):
    rules = [item(kind='rule', format='sigma', text='title: CVE-2026-12345')]
    sources = [{'id': 'test-feed', 'name': 'Rules', 'kind': 'rule', 'url': 'https://example.org/rules', 'status': 'ok', 'items': 1}]
    response = upload(auth_client, bundle(rules, manifest_change={'sources': sources}))
    assert response.status_code == 200, response.text
    assert response.json()['news_total'] == 0
    assert db_session.scalar(select(func.count()).select_from(VmTrendPublication)) == 0
    assert auth_client.get('/api/siem/hunting/intel?kind=rule').json()['total'] == 1


def test_projection_failure_rolls_back_archive_and_news(auth_client, db_session, monkeypatch):
    from api.modules.vm.services.trends import news_archive
    original = news_archive.project_news
    def fail_after_projection(db):
        original(db)
        raise RuntimeError('test projection failure')
    monkeypatch.setattr(news_archive, 'project_news', fail_after_projection)
    with pytest.raises(RuntimeError, match='test projection failure'):
        upload(auth_client, bundle())
    assert db_session.scalar(select(func.count()).select_from(ThIntelImport)) == 0
    assert db_session.scalar(select(func.count()).select_from(ThIntelItem)) == 0
    assert db_session.scalar(select(func.count()).select_from(VmTrendPublication)) == 0


def test_archive_decisions_and_source_filter_survive_full_sync(auth_client, db_session):
    assert upload(auth_client, bundle()).status_code == 200
    url = '/api/vm/trends/CVE-2026-12345'
    detail = auth_client.get(url+'?period=all').json()
    evidence = detail['evidence'][0]
    review = auth_client.patch(url+'/review', json={'version': detail['version'],
        'publication_key': evidence['publication_key'], 'revision': evidence['revision'],
        'rejected': True, 'note': 'Already assessed'})
    assert review.status_code == 200, review.text
    sources = auth_client.get('/api/vm/trends/publication-sources').json()['items']
    assert sources == [{'id': db_session.scalar(select(VmTrendPublication)).source_id, 'name': 'Test feed'}]
    apply_page(db_session, page(), reset=True)
    process_pending(db_session)
    evidence = auth_client.get(url+'?period=all').json()['evidence']
    archived = next(e for e in evidence if e['publication_key'].startswith('archive-'))
    assert archived['rejected']


def test_news_visible_during_interrupted_first_collector_download(auth_client, db_session):
    data = page()
    apply_page(db_session, {**data, 'events': data['events'][:1], 'next_cursor': 1, 'has_more': True})
    import_bundle(db_session, bundle(), 'legacy')
    process_pending(db_session)
    assert listing(auth_client)['total'] == 1
    state = db_session.get(VmTrendIngestState, 1)
    assert state.active_generation != state.generation
    assert state.cursor == 1
    assert upload(auth_client, bundle()).status_code == 200
    assert listing(auth_client)['total'] == 1
    apply_page(db_session, data)
    process_pending(db_session)
    evidence = auth_client.get('/api/vm/trends/CVE-2026-12345?period=all').json()['evidence']
    assert len(evidence) == 2


def test_zip_filter_excludes_collector_only_cards(auth_client, db_session):
    apply_page(db_session, page())
    process_pending(db_session)
    params = {'view': 'archive', 'period': 'all', 'from_archive': True}
    assert auth_client.get('/api/vm/trends', params=params).json()['total'] == 0
    assert upload(auth_client, bundle([item(title='New CVE-2026-88888', text='Security vulnerability CVE-2026-88888')])).status_code == 200
    filtered = auth_client.get('/api/vm/trends', params=params).json()
    assert [r['id'] for r in filtered['items']] == ['CVE-2026-88888']
    assert listing(auth_client, 'archive')['total'] == 2


def test_zip_filter_displays_archive_article_for_shared_cve(auth_client, db_session):
    apply_page(db_session, page())
    process_pending(db_session)
    assert upload(auth_client, bundle()).status_code == 200
    params = {'view': 'archive', 'period': 'all', 'from_archive': True}
    row = auth_client.get('/api/vm/trends', params=params).json()['items'][0]
    assert row['title'] == item()['title']
    assert row['source_url'] == item()['url']
    assert row['publication_count'] == 1
    assert row['last_event_at'].startswith('2026-11-01')
    detail = auth_client.get('/api/vm/trends/CVE-2026-12345?period=all').json()
    assert detail['evidence_total'] == 2
