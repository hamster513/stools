import datetime as dt
import json
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select

from api.modules.assets.models import Asset, AssetUser
from api.modules.siem.logons.client import TableError, TablesClient
from api.modules.siem.logons.models import SiemLogon
from api.modules.siem.logons.schemas import ImportConfig, normalize
from api.modules.siem.logons.service import persist


def config(**kw):
    return ImportConfig(table_name='Logons', **kw)


def row(src='192.0.2.1', time='2026-11-12T12:43:46Z'):
    return {'user': 'Alice', 'domain': 'example.test', 'dst_host': 'dc.example.test',
            'dst_ip': '', 'src_host': src, 'src_ip': src, '_last_changed': time}


def test_normalize_aliases_and_timestamp():
    r = normalize(row(), config())
    assert r.user == 'alice' and r.domain == 'example.test'
    assert r.src_host == '' and r.src_ip == '192.0.2.1'
    assert r.last_login == dt.datetime(2026, 11, 12, 12, 43, 46, tzinfo=dt.UTC)
    c = config(mapping={'user': 'Account', 'domain': 'Domain', 'last_login': 'Time',
                        'dst_host': 'Server', 'dst_ip': '', 'src_host': '', 'src_ip': ''})
    assert normalize({'Account': 'alice', 'Domain': 'example.test', 'Time': row()['_last_changed'],
                      'Server': 'DC.EXAMPLE.TEST'}, c).dst_host == 'dc.example.test'


@pytest.mark.parametrize('field,value', [('user', ''), ('_last_changed', 'bad'),
    ('_last_changed', '2026-11-12T12:00:00'), ('dst_ip', 'not-an-ip'), ('domain', '')])
def test_invalid_rows(field, value):
    r = row(); r[field] = value
    with pytest.raises(ValueError):
        normalize(r, config())


def test_pages_and_remote_error():
    offsets = []
    def handle(req):
        if req.method == 'GET':
            return httpx.Response(200, json=[{'name': 'Logons', 'token': 'table-token'}])
        body = json.loads(req.content); offsets.append(body['offset'])
        assert body['limit'] == 2
        return httpx.Response(200, json={'items': [row()] * (2 if body['offset'] == 0 else 1)})
    conn = SimpleNamespace(host='siem.example.test', api_token='secret', verify_tls=True)
    with httpx.Client(transport=httpx.MockTransport(handle)) as http:
        c = TablesClient(conn, http)
        assert len(list(c.rows('Logons', batch_size=2))) == 3
    assert offsets == [0, 2]
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(403, text='secret'))) as http:
        with pytest.raises(TableError, match='403') as e:
            TablesClient(conn, http).catalog()
        assert 'secret' not in str(e.value)


def test_upsert_preserves_sources_and_newest_time(db_session):
    db = db_session
    user = AssetUser(name_key='example.test\\alice', sam='alice', domain='example.test', note='keep')
    host = Asset(name='dc', name_key='dc', fqdn='dc.example.test')
    db.add_all([user, host]); db.commit()
    records = [normalize(row(), config()), normalize(row('192.0.2.2'), config())]
    persist(db, 'scope', 'Logons', records)
    db.commit()
    persist(db, 'scope', 'Logons', [normalize(row(time='2026-11-11T00:00:00Z'), config())])
    db.commit()
    saved = list(db.scalars(select(SiemLogon).limit(10)))
    assert len(saved) == 2
    assert {r.user_id for r in saved} == {user.id}
    assert {r.dst_asset_id for r in saved} == {host.id}
    assert saved[0].last_login.day == 12
    assert db.get(AssetUser, user.id).note == 'keep'


def test_ambiguous_host_not_linked(db_session):
    db = db_session
    db.add_all([Asset(fqdn='dc.example.test'), Asset(fqdn='dc.example.test')]); db.commit()
    result = persist(db, 'scope', 'Logons', [normalize(row(), config())]); db.commit()
    saved = db.scalar(select(SiemLogon).limit(1))
    assert saved.dst_asset_id is None
    assert result['unresolved_hosts'] == 2


def test_settings_and_schedule_rbac(auth_client, client_as, make_user):
    payload = config().model_dump(mode='json')
    assert auth_client.put('/api/siem/logons/settings', json=payload).status_code == 200
    assert auth_client.get('/api/siem/logons/settings').json()['config']['table_name'] == 'Logons'
    jobs = auth_client.get('/api/settings/schedules').json()['items']
    assert any(x['module'] == 'siem' and x['kind'] == 'logons' for x in jobs)
    with client_as('auditor') as c:
        assert c.put('/api/siem/logons/settings', json=payload).status_code == 403
        assert c.post('/api/siem/logons/run').status_code == 403


def configure_remote(db, monkeypatch, handler):
    from api.modules.siem.logons.service import save_config
    from api.modules.siem.services.kb_settings import KbConnectionIn, save_connection
    save_connection(db, KbConnectionIn(host='siem.example.test', api_token='test-token'), 'test')
    save_config(db, config(), 'test')
    monkeypatch.setattr('api.modules.siem.logons.client.make_client',
                        lambda _: httpx.Client(transport=httpx.MockTransport(handler)))


def test_run_preview_and_read_in_cards(auth_client, db_session, monkeypatch):
    def handler(req):
        if req.method == 'GET':
            return httpx.Response(200, json=[{'name': 'Logons', 'token': 'token-id'}])
        return httpx.Response(200, json={'items': [row(), row('192.0.2.2')]})
    configure_remote(db_session, monkeypatch, handler)
    db_session.add(Asset(fqdn='dc.example.test')); db_session.commit()
    preview = auth_client.post('/api/siem/logons/preview', json=config().model_dump())
    assert preview.status_code == 200
    assert len(preview.json()['items']) == 2
    result = auth_client.post('/api/siem/logons/run')
    assert result.status_code == 202
    job = auth_client.get(f"/api/siem/logons/jobs/{result.json()['job_id']}").json()
    assert job['status'] == 'done', job
    logons = auth_client.get('/api/assets/logons').json()
    assert logons['total'] == 2
    uid, aid = logons['items'][0]['user_id'], logons['items'][0]['dst_asset_id']
    assert uid and aid
    assert auth_client.get(f'/api/assets/logons?user_id={uid}').json()['total'] == 2
    assert auth_client.get(f'/api/assets/logons?asset_id={aid}').json()['total'] == 2
    detail = auth_client.get(f'/api/assets/users/{uid}').json()
    assert any(s['source'] == 'siem' for s in detail['sources'])
    auth_client.post('/api/siem/logons/run')
    assert auth_client.get('/api/assets/logons').json()['total'] == 2


@pytest.mark.parametrize('failure', ['page', 'invalid', 'limit'])
def test_failed_import_does_not_persist_partial(auth_client, db_session, monkeypatch, failure):
    from api.modules.siem.logons.service import save_config
    def handler(req):
        if req.method == 'GET':
            return httpx.Response(200, json=[{'name': 'Logons', 'token': 't'}])
        body = json.loads(req.content)
        if failure == 'page' and body['offset']:
            return httpx.Response(500, text='private upstream details')
        items = [row()] * 1000 if failure == 'page' else [row(), row(time='invalid') if failure == 'invalid' else row('192.0.2.2')]
        return httpx.Response(200, json={'items': items})
    configure_remote(db_session, monkeypatch, handler)
    if failure == 'limit':
        save_config(db_session, config(max_rows=1), 'test')
    result = auth_client.post('/api/siem/logons/run')
    job = auth_client.get(f"/api/siem/logons/jobs/{result.json()['job_id']}").json()
    assert job['status'] == 'failed'
    assert 'private upstream details' not in job['error']
    assert auth_client.get('/api/assets/logons').json()['total'] == 0
    assert db_session.scalar(select(AssetUser).limit(1)) is None


def test_conflicting_host_and_ambiguous_user_remain_unlinked(db_session):
    db = db_session
    db.add_all([Asset(fqdn='dc.example.test', ip='192.0.2.10'), Asset(fqdn='other.example.test', ip='192.0.2.11'),
                AssetUser(name_key='example.test\\alice'), AssetUser(name_key='example.test\\alice')])
    db.commit()
    raw = row(); raw['dst_ip'] = '192.0.2.11'
    persist(db, 'scope', 'Logons', [normalize(raw, config())]); db.commit()
    item = db.scalar(select(SiemLogon).limit(1))
    assert item.user_id is None and item.dst_asset_id is None


def test_analyst_can_run_but_cannot_change_config(client_as):
    c = client_as({'siem': 'write'})
    assert c.put('/api/siem/logons/settings', json=config().model_dump()).status_code == 403
    assert c.post('/api/siem/logons/preview', json=config().model_dump()).status_code == 403
    assert c.post('/api/siem/logons/run').status_code == 400  # нет подключения, права достаточны
    assert c.get('/api/assets/logons').status_code == 403


def test_settings_reject_invalid_mapping_and_unknown_fields(auth_client):
    for patch in [{'mapping': {'user': '', 'dst_host': ''}}, {'unexpected': True}, {'max_rows': 0}]:
        data = config().model_dump(); data.update(patch)
        assert auth_client.put('/api/siem/logons/settings', json=data).status_code == 422


def test_netbios_alias_with_dns_domain():
    raw = row(); raw['user'] = 'EXAMPLE\\Alice'
    assert normalize(raw, config(), {'example': 'example.test'}).domain == 'example.test'


def test_logons_survive_asset_merge(auth_client, db_session):
    from api.modules.assets.services.assets import merge_assets
    db = db_session
    old = Asset(name='dc', fqdn='dc.example.test')
    survivor = Asset(name='canonical', fqdn='canonical.example.test')
    db.add_all([old, survivor]); db.commit()
    persist(db, 'scope', 'Logons', [normalize(row(), config())]); db.commit()
    merge_assets(db, survivor.id, old.id, 'test'); db.commit()
    result = auth_client.get(f'/api/assets/logons?asset_id={survivor.id}').json()
    assert result['total'] == 1
    assert result['items'][0]['dst_asset_id'] == survivor.id
    persist(db, 'scope', 'Logons', [normalize(row(), config())]); db.commit()
    assert db.scalar(select(SiemLogon).limit(1)).dst_asset_id == survivor.id


def test_cancel_during_persist_rolls_back(auth_client, db_session, monkeypatch):
    from sqlalchemy.orm import Session

    from api.modules.siem.logons import service
    from api.modules.siem.logons.models import SiemLogonJob
    def handler(req):
        if req.method == 'GET':
            return httpx.Response(200, json=[{'name': 'Logons', 'token': 't'}])
        return httpx.Response(200, json={'items': [row()]})
    configure_remote(db_session, monkeypatch, handler)
    original = service.persist
    def cancel(db, *args):
        result = original(db, *args)
        with Session(db.get_bind()) as side:
            job = side.scalar(select(SiemLogonJob).where(SiemLogonJob.status == 'running').limit(1))
            job.cancel_requested = True
            side.commit()
        return result
    monkeypatch.setattr(service, 'persist', cancel)
    result = auth_client.post('/api/siem/logons/run')
    job = auth_client.get(f"/api/siem/logons/jobs/{result.json()['job_id']}").json()
    assert job['status'] == 'cancelled'
    assert auth_client.get('/api/assets/logons').json()['total'] == 0
    assert db_session.scalar(select(AssetUser).limit(1)) is None
