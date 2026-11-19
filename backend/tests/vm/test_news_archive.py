"""Offline ZIP news must enter VM's publication pipeline, without SIEM rights."""
import random
from base64 import b64encode

import pytest
from sqlalchemy import func, select

from api.limits import DEFAULT_LIMIT
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


def test_news_zip_larger_than_default_body_limit(client_as):
    rng = random.Random(0)
    articles = []
    for i in range(10):
        text = b64encode(rng.randbytes(230_000)).decode('ascii').ljust(930_000)
        articles.append(item(external_id=f'news-{i}', url=f'https://example.org/news/{i}', text=text))
    data = bundle(articles)
    assert len(data) > DEFAULT_LIMIT

    client = client_as({'vm': 'admin'})
    response = upload(client, data)
    assert response.status_code == 200, (len(data), response.text)
    assert response.json()['added'] == len(articles)
    repeated = upload(client, data).json()
    assert repeated['duplicate'] and repeated['news_total'] == len(articles)


def test_news_archive_size_boundary(auth_client, monkeypatch):
    data = bundle()
    monkeypatch.setattr('api.modules.siem.hunting.intel.MAX_ZIP', len(data))
    assert upload(auth_client, data).status_code == 200
    monkeypatch.setattr('api.modules.siem.hunting.intel.MAX_ZIP', len(data) - 1)
    response = upload(auth_client, data)
    assert response.status_code == 413
    assert response.json()['detail'] == 'Архив превышает 64 МиБ'


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


def test_telegram_archive_keeps_channel_identity_links_and_edited_post(auth_client, db_session):
    from api.modules.vm.trend_models import VmTrendSource
    channels = ['WMXWAS', 'cyberok_news']
    articles = [item(source_id=channel.lower(), external_id='42',
                     title='Уязвимость CVE-2026-12345', url=f'https://t.me/{channel}/42',
                     text='CVE-2026-12345 https://example.org/advisory', full_text=True)
                for channel in channels]
    sources = [{'id': channel.lower(), 'name': '@'+channel, 'kind': 'news',
                'url': 'https://t.me/'+channel, 'status': 'ok', 'items': 1} for channel in channels]
    data = bundle(articles, manifest_change={'sources': sources})
    assert upload(auth_client, data).status_code == 200
    publications = list(db_session.scalars(select(VmTrendPublication).limit(10)))
    assert len(publications) == 2
    assert {p.data['publisher_id'] for p in publications} == {'telegram:wmxwas', 'telegram:cyberok_news'}
    assert all(p.data['origin_adapter'] == 'telegram' for p in publications)
    assert all('https://example.org/advisory' in p.data['links'] for p in publications)
    configs = list(db_session.scalars(select(VmTrendSource).limit(10)))
    assert {s.data['telegram_channel'] for s in configs} == {'wmxwas', 'cyberok_news'}
    assert all(s.data['telegram_mode'] == 'web' and not s.data['llm_allowed'] for s in configs)
    assert listing(auth_client)['items'][0]['id'] == 'CVE-2026-12345'
    assert upload(auth_client, data).json()['duplicate']
    articles[0]['text'] = 'CVE-2026-12345 Edited publication'
    assert upload(auth_client, bundle(articles, manifest_change={'sources': sources})).status_code == 200
    assert db_session.scalar(select(func.count()).select_from(VmTrendPublication)) == 2
    db_session.expire_all()
    assert any('Edited' in p.data['text'] for p in db_session.scalars(select(VmTrendPublication).limit(10)))
