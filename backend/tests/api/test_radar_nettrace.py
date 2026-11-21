import copy

import pytest
from sqlalchemy import func, select

from api.modules.radar import nettrace_router as routes
from api.modules.radar import nettrace_service as service
from api.modules.radar.models import (
    NettraceConfig,
    NettraceDevice,
    NettraceEvaluation,
    NettraceSnapshot,
)
from api.modules.radar.nettrace_client import SnapshotChanged
from api.platform.sync_queue import worker
from api.platform.sync_queue.models import SyncRun

BASE = '/api/radar/nettrace'
DEVICE = '11111111-1111-1111-1111-111111111111'
SET = 'set-0123456789abcdef'
STAMP = '2026-11-20T10:00:00Z'
SNAP = {'id': SET, 'oldest_collected_at': STAMP, 'newest_collected_at': STAMP,
        'devices': [{'device': {'id': DEVICE, 'name': 'edge'}, 'topology_snapshot': {'id': 't1', 'collected_at': STAMP},
                     'policy_snapshot': {'id': 'p1', 'collected_at': STAMP}}]}
BODY = {'source': {'address': '198.51.100.25'}, 'destination': {'address': '203.0.113.15', 'port': 443}, 'protocol': 'tcp'}


def result(body=None):
    return {'evaluation_id': 'result-id', 'evaluated_at': STAMP, 'snapshot_set_id': SET, 'request': body or BODY,
            'verdict': 'allowed', 'complete': True, 'truncated': False, 'missing_data': [], 'reasons': [],
            'limitations': service.ALWAYS_LIMITATIONS,
            'snapshots': copy.deepcopy(SNAP['devices']),
            'paths': [{'path_id': 'path-1', 'verdict': 'allowed', 'reasons': [], 'missing_data': [],
                       'hops': [{'index': 1, 'device': {'id': DEVICE, 'name': 'edge'}, 'decision': 'permit',
                                 'packet_before': {'destination_port': 443}, 'packet_after': {'destination_port': 443},
                                 'snapshots': {'topology': {'id': 't1'}, 'policy': {'id': 'p1'}}}]}]}


class Fake:
    def __init__(self):
        self.calls = []
        self.changed = False
        self.race = False
        self.conflict_once = False
        self.path_calls = 0
        self.snap = copy.deepcopy(SNAP)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def request(self, method, path, **kwargs):
        self.calls.append((method, path))
        if path == '/snapshot-set':
            return copy.deepcopy(self.snap)
        if path == '/path-evaluations':
            self.path_calls += 1
            if self.conflict_once and self.path_calls == 1:
                raise SnapshotChanged('changed')
            data = result({k: v for k, v in kwargs['body'].items() if k != 'snapshot_set_id'})
            if self.race:
                data['paths'][0]['hops'][0]['snapshots']['policy']['id'] = 'p2'
            return data
        return {'total': 1, 'items': []}

    def pages(self, path, **kwargs):
        if path == '/devices':
            return [{'id': DEVICE, 'name': 'edge', 'platform': 'asa'}], {'total': 1}
        if path.endswith('/interfaces'):
            return [{'name': 'outside', 'ip': '203.0.113.1', 'network': '203.0.113.0/24'}], {'snapshot': {'id': 't1'}}
        return [], {'snapshot': {'id': 'p2' if self.changed else 'p1'}, 'status': 'ok'}


@pytest.fixture
def fake(monkeypatch):
    client = Fake()
    monkeypatch.setattr(service, 'make_client', lambda *args: client)
    monkeypatch.setattr(routes, 'make_client', lambda *args: client)
    from api import collector_routes
    monkeypatch.setattr(collector_routes, 'spawn', lambda fn: fn())
    return client


def configure(client):
    response = client.put(BASE + '/settings', json={'url': 'https://nettrace.example', 'api_token': 'ntk_test_SECRET', 'enabled': True})
    assert response.status_code == 200, response.text
    return response.json()


def drain(db, run_id):
    for _ in range(8):
        worker.dispatch(db)
        db.expire_all()
        run = db.get(SyncRun, run_id)
        if run.status in ('done', 'failed', 'cancelled', 'partial'):
            return run
    raise AssertionError('Queue did not finish')


def test_settings_encryption_permissions_and_no_secret_echo(auth_client, client_as, db_session):
    cfg = configure(auth_client)
    assert cfg['api_token_set'] and 'SECRET' not in str(cfg)
    assert db_session.get(NettraceConfig, 1).token_encrypted.startswith('enc:v1:')
    for levels in ({}, {'radar': 'read'}, {'radar': 'write'}):
        client = client_as(levels)
        assert client.get(BASE + '/settings').status_code == 403
        assert client.put(BASE + '/settings', json={'enabled': False}).status_code == 403
        assert client.post(BASE + '/test').status_code == 403
    assert auth_client.put(BASE + '/settings', json={'url': 'https://other.example', 'enabled': True}).status_code == 422
    assert auth_client.put(BASE + '/settings', json={'url': 'http://nettrace.example', 'enabled': True}).status_code == 422


def test_sync_uses_common_queue_atomic_inventory_and_schedule(auth_client, db_session, fake):
    configure(auth_client)
    queued = auth_client.post(BASE + '/sync')
    assert queued.status_code == 202
    assert auth_client.get(BASE + '/inventory').json()['total'] == 0
    run = drain(db_session, queued.json()['run_id'])
    assert run.status == 'done'
    inventory = auth_client.get(BASE + '/inventory').json()
    assert inventory['total'] == 1 and inventory['items'][0]['name'] == 'edge'
    assert auth_client.get(BASE + '/devices/' + str(inventory['items'][0]['id'])).status_code == 200
    assert any(t['module'] == 'radar' for t in auth_client.get('/api/settings/schedules').json()['items'])
    second = auth_client.post(BASE + '/sync').json()
    assert drain(db_session, second['run_id']).status == 'done'
    assert db_session.scalar(select(func.count()).select_from(NettraceSnapshot)) == 1
    fake.snap['id'] = 'set-1123456789abcdef'
    fake.changed = True
    bad = auth_client.post(BASE + '/sync').json()
    assert drain(db_session, bad['run_id']).status == 'failed'
    assert auth_client.get(BASE + '/inventory').json()['snapshot']['snapshot_set_id'] == SET
    assert db_session.scalar(select(func.count()).select_from(NettraceDevice)) == 1


def test_evaluation_queue_cache_and_snapshot_race(auth_client, db_session, fake):
    configure(auth_client)
    first = auth_client.post(BASE + '/evaluations', json=BODY)
    assert first.status_code == 202
    assert drain(db_session, first.json()['run_id']).status == 'done'
    detail = auth_client.get(BASE + '/evaluations/' + str(first.json()['id'])).json()
    assert detail['verdict'] == 'allowed' and detail['consistent'] and detail['warnings']
    second = auth_client.post(BASE + '/evaluations', json=BODY).json()
    assert drain(db_session, second['run_id']).status == 'done'
    assert fake.path_calls == 1
    assert auth_client.get(BASE + '/evaluations/' + str(second['id'])).json()['cached_from'] == first.json()['id']
    fake.race = True
    third = auth_client.post(BASE + '/evaluations', json={**BODY, 'protocol': 'udp'}).json()
    assert drain(db_session, third['run_id']).status == 'done'
    detail = auth_client.get(BASE + '/evaluations/' + str(third['id'])).json()
    assert detail['verdict'] == 'unknown' and not detail['consistent']
    assert fake.path_calls == 3


def test_conflict_retries_and_config_change_invalidates_queued(auth_client, db_session, fake):
    configure(auth_client)
    fake.conflict_once = True
    item = auth_client.post(BASE + '/evaluations', json=BODY).json()
    assert drain(db_session, item['run_id']).status == 'done'
    assert fake.path_calls == 2
    queued = auth_client.post(BASE + '/evaluations', json=BODY).json()
    configure(auth_client)  # token rotation increments generation
    assert drain(db_session, queued['run_id']).status == 'failed'
    assert fake.path_calls == 2
    record = db_session.get(NettraceEvaluation, queued['id'])
    assert record.response is None


def test_readers_cannot_run_and_inputs_are_strict(auth_client, client_as, fake):
    configure(auth_client)
    reader = client_as({'radar': 'read'})
    assert reader.get(BASE + '/inventory').status_code == 200
    assert reader.post(BASE + '/sync').status_code == 403
    assert reader.post(BASE + '/evaluations', json=BODY).status_code == 403
    assert auth_client.post(BASE + '/evaluations', json={**BODY, 'source': {'address': '::1'}}).status_code == 422
    assert auth_client.post(BASE + '/evaluations', json={**BODY, 'source': {'address': '198.51.100.25', 'port': 1}}).status_code == 422


def test_cancel_queued_calculation_and_cache_expires(auth_client, db_session, fake):
    import datetime as dt
    configure(auth_client)
    queued = auth_client.post(BASE + '/evaluations', json=BODY).json()
    assert auth_client.post(f"/api/settings/sync-runs/{queued['run_id']}/cancel").status_code == 200
    assert drain(db_session, queued['run_id']).status == 'cancelled'
    assert fake.path_calls == 0
    first = auth_client.post(BASE + '/evaluations', json=BODY).json()
    assert drain(db_session, first['run_id']).status == 'done'
    record = db_session.get(NettraceEvaluation, first['id'])
    record.finished_at = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=16)
    db_session.commit()
    next_item = auth_client.post(BASE + '/evaluations', json=BODY).json()
    assert drain(db_session, next_item['run_id']).status == 'done'
    assert fake.path_calls == 2


def test_pacing_is_persistent_and_cancellable(auth_client, db_session, monkeypatch):
    from api.jobs import JobCancelled
    configure(auth_client)
    waits = []
    monkeypatch.setattr(service, '_wait', lambda seconds, handle: waits.append(seconds))
    cfg = db_session.get(NettraceConfig, 1)
    service.paced(db_session, cfg.generation, True, None)
    service.paced(db_session, cfg.generation, True, None)
    assert len(waits) == 2 and 1.5 < waits[1] <= 2.1
    class Cancelled:
        def cancelled(self):
            return True
    with pytest.raises(JobCancelled):
        service.paced(db_session, cfg.generation, False, Cancelled())


@pytest.mark.parametrize('change', ['empty_paths', 'empty_hops', 'wrong_request'])
def test_malformed_result_cannot_confirm_access(change):
    from api.modules.radar.nettrace_client import NettraceError
    response = result()
    if change == 'empty_paths':
        response['paths'] = []
    elif change == 'empty_hops':
        response['paths'][0]['hops'] = []
    else:
        response['request'] = {**BODY, 'protocol': 'udp'}
    with pytest.raises(NettraceError):
        service.assess(SNAP, SNAP, response, BODY)


def test_missing_snapshot_and_incomplete_result_fail_closed():
    response = result()
    response['snapshots'] = []
    verdict, consistent, warnings = service.assess(SNAP, SNAP, response, BODY)
    assert verdict == 'unknown' and not consistent and warnings
    response = result()
    response['truncated'] = True
    assert service.assess(SNAP, SNAP, response, BODY)[0] == 'conditional'
    response['verdict'] = 'blocked'
    assert service.assess(SNAP, SNAP, response, BODY)[0] == 'unknown'


def test_real_client_contract_feeds_atomic_sync(auth_client, db_session, monkeypatch):
    import httpx

    from api.modules.radar.nettrace_client import NettraceClient
    configure(auth_client)
    requested = []
    def handler(req):
        requested.append(req.url.path)
        assert req.headers['authorization'] == 'Bearer ntk_fixture'
        suffix = req.url.path.removeprefix('/api/ext/v1')
        if suffix == '/snapshot-set':
            data = SNAP
        elif suffix == '/devices':
            data = {'total': 1, 'items': [{'id': DEVICE, 'name': 'edge'}]}
        elif suffix.endswith('/interfaces'):
            data = {'snapshot': {'id': 't1'}, 'total': 1, 'items': [{'name': 'outside'}]}
        else:
            data = {'snapshot': {'id': 'p1'}, 'status': 'ok', 'total': 0, 'items': []}
        return httpx.Response(200, json=data)
    monkeypatch.setattr(service, 'make_client', lambda *args: NettraceClient('https://nettrace.example', 'ntk_fixture', transport=httpx.MockTransport(handler)))
    outcome = service.synchronize(db_session)
    assert outcome['devices'] == 1
    assert len(requested) == 6
    assert auth_client.get(BASE + '/inventory').json()['items'][0]['interfaces_count'] == 1


def test_radar_schedule_uses_radar_rights(client_as):
    from api.rbac import needed
    url = '/api/settings/schedules/radar/nettrace_sync/0'
    assert needed('PUT', url) == ('radar', 'admin')
    assert needed('PUT', url + '/dependencies') is None
    reader = client_as({'radar': 'read'})
    assert reader.put(url, json={}).status_code == 403
    admin = client_as({'radar': 'admin'})
    response = admin.put(url, json={'enabled': False, 'interval_hours': 24})
    assert response.status_code == 200, response.text


def test_unknown_nat_port_or_mixed_paths_cannot_confirm_access():
    response = result()
    response['paths'][0]['hops'][0]['packet_after']['destination_port'] = None
    assert service.assess(SNAP, SNAP, response, BODY)[0] == 'conditional'
    response = result()
    response['paths'][0]['verdict'] = 'unknown'
    assert service.assess(SNAP, SNAP, response, BODY)[0] == 'conditional'
