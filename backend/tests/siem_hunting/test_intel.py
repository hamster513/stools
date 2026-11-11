import datetime as dt
import hashlib
import io
import json
import zipfile

import pytest
from sqlalchemy import func, select

from api.modules.siem.hunting.models import ThHunt

URL = '/api/siem/hunting/intel'


def item(**kw):
    return {'source_id': 'test-feed', 'external_id': 'article-1', 'kind': 'news',
            'title': 'Новая кампания T1059', 'url': 'https://example.org/report',
            'text': 'Описание CVE-2026-12345', 'format': 'article',
            'published_at': '2026-11-01T12:00:00Z', 'technique_ids': ['T1059'], 'full_text': False, **kw}


def bundle(items=None, *, date=None, manifest_change=None, extra=None):
    items = items if items is not None else [item()]
    data = ''.join(json.dumps(i, ensure_ascii=False)+'\n' for i in items).encode()
    manifest = {'format': 'stools-th-intel', 'version': 1,
                'generated_at': date or dt.datetime.now(dt.UTC).isoformat(), 'items_count': len(items),
                'items_sha256': hashlib.sha256(data).hexdigest(),
                'sources': [{'id': 'test-feed', 'name': 'Test feed', 'kind': 'news',
                             'url': 'https://example.org/feed', 'status': 'ok', 'items': len(items)}]}
    manifest.update(manifest_change or {})
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('manifest.json', json.dumps(manifest))
        z.writestr('items.jsonl', data)
        if extra: z.writestr(*extra)
    return output.getvalue()


def upload(client, data):
    return client.post(URL+'/import', files={'file': ('intel.zip', data, 'application/zip')})


def test_import_list_detail_and_no_executable_hunts(auth_client, db_session):
    before = db_session.scalar(select(func.count()).select_from(ThHunt))
    response = upload(auth_client, bundle())
    assert response.status_code == 200, response.text
    assert response.json()['added'] == 1
    listing = auth_client.get(URL, params={'q': 'T1059', 'kind': 'news'}).json()
    assert listing['total'] == 1
    row = listing['items'][0]
    assert 'text' not in row
    detail = auth_client.get(URL+'/'+row['id']).json()
    assert detail['text'] == item()['text']
    assert detail['source']['name'] == 'Test feed'
    assert db_session.scalar(select(func.count()).select_from(ThHunt)) == before
    assert auth_client.get(URL+'/imports').json()['items'][0]['added'] == 1


def test_repeat_and_older_archive_cannot_roll_back(auth_client):
    first = bundle(date='2026-11-02T00:00:00Z')
    assert upload(auth_client, first).json()['added'] == 1
    assert upload(auth_client, first).json()['duplicate'] is True
    changed = bundle([item(text='Новая версия')], date='2026-11-03T00:00:00Z')
    assert upload(auth_client, changed).json()['updated'] == 1
    old = bundle([item(text='Старая версия')], date='2026-11-01T00:00:00Z')
    assert upload(auth_client, old).json()['stale'] == 1
    row = auth_client.get(URL).json()['items'][0]
    assert auth_client.get(URL+'/'+row['id']).json()['text'] == 'Новая версия'
    assert auth_client.get(URL).json()['total'] == 1


@pytest.mark.parametrize('change', [{'items_sha256': '0'*64}, {'items_count': 99}, {'version': 2},
                                   {'generated_at': '2099-01-01T00:00:00Z'}])
def test_bad_manifest_is_atomic(auth_client, change):
    response = upload(auth_client, bundle(manifest_change=change))
    assert response.status_code == 422
    assert auth_client.get(URL).json()['total'] == 0


@pytest.mark.parametrize('data', [b'not a zip', bundle(extra=('../escape', 'x')),
                                bundle([item(), item()]), bundle([item(url='javascript:alert(1)')]),
                                bundle([item(source_id='unknown')]), bundle([item(technique_ids=['bad'])])])
def test_untrusted_archive_rejected(auth_client, data):
    assert upload(auth_client, data).status_code == 422
    assert auth_client.get(URL).json()['total'] == 0


def test_partial_source_failures_are_visible_and_do_not_delete(auth_client):
    assert upload(auth_client, bundle()).json()['added'] == 1
    source = {'id': 'unavailable', 'name': 'Unavailable', 'kind': 'news', 'url': 'https://example.org/offline',
              'status': 'error', 'items': 0, 'error': 'HTTP 503'}
    response = upload(auth_client, bundle([], manifest_change={'sources': [source]}))
    assert response.status_code == 200
    assert response.json()['sources'][0]['status'] == 'error'
    assert auth_client.get(URL).json()['total'] == 1


def test_rules_remain_source_text_and_license_is_preserved(auth_client):
    source = {'id': 'test-feed', 'name': 'Rules', 'kind': 'rule', 'url': 'https://github.com/example/rules',
              'status': 'ok', 'items': 1, 'revision': 'a'*40,
              'license_text': 'Original license', 'license_url': 'https://example.org/license'}
    raw = 'title: Test\ndetection:\n  condition: selection\n'
    response = upload(auth_client, bundle([item(kind='rule', format='sigma', text=raw)], manifest_change={'sources': [source]}))
    assert response.status_code == 200
    row = auth_client.get(URL, params={'kind': 'rule'}).json()['items'][0]
    detail = auth_client.get(URL+'/'+row['id']).json()
    assert detail['text'] == raw
    assert detail['source']['revision'] == 'a'*40
    assert detail['source']['license_text'] == 'Original license'


def test_import_requires_siem_admin(client_as):
    for role in ['read', 'write']:
        client = client_as({'siem': role})
        assert client.get(URL).status_code == 200
        assert upload(client, bundle()).status_code == 403
    assert upload(client_as({'siem': 'admin'}), bundle()).status_code == 403
    assert upload(client_as({'siem': 'admin', 'vm': 'admin'}), bundle()).status_code == 200


def test_anonymous_and_paging_validation(client):
    assert client.get(URL).status_code == 401
    assert upload(client, bundle()).status_code == 401


def test_listing_filters_and_paging(auth_client):
    assert upload(auth_client, bundle([item(external_id=str(i), title=f'Article {i}') for i in range(4)])).status_code == 200
    page = auth_client.get(URL, params={'limit': 2, 'offset': 2}).json()
    assert page['total'] == 4 and len(page['items']) == 2
    assert auth_client.get(URL, params={'q': 'Article 3'}).json()['total'] == 1
    assert auth_client.get(URL, params={'limit': 501}).status_code == 422


def test_validation_finishes_before_any_write(auth_client):
    response = upload(auth_client, bundle([item(), item(external_id='bad', text='bad\x00text')]))
    assert response.status_code == 422
    assert auth_client.get(URL).json()['total'] == 0
    assert auth_client.get(URL+'/imports').json()['items'] == []


def test_expanded_size_limit(auth_client, monkeypatch):
    monkeypatch.setattr('api.modules.siem.hunting.intel.MAX_DATA', 10)
    assert upload(auth_client, bundle()).status_code == 422


def test_unknown_material_and_empty_filter(auth_client):
    assert auth_client.get(URL+'/not-found').status_code == 404
    assert auth_client.get(URL, params={'kind': 'anything'}).status_code == 422
