import datetime as dt
import os
import time
from sqlalchemy import func, select
from api.platform.storage_usage import service
from api.platform.storage_usage.files import measure_files
from api.platform.storage_usage.models import StorageSample
from api.platform.scheduler import tick
from api.platform.sync_queue.worker import dispatch

URL = '/api/settings/storage'

def test_files_no_symlink_or_hardlink_double_count(tmp_path):
    (tmp_path / 'ad').mkdir()
    file = tmp_path / 'ad' / 'one.gz'
    file.write_bytes(b'x' * 10000)
    os.link(file, tmp_path / 'ad' / 'two.gz')
    (tmp_path / 'outside').symlink_to('/etc')
    result = measure_files(tmp_path)
    assert result['bytes'] == file.stat().st_blocks * 512
    assert result['modules']['ad'] == result['bytes']
    assert result['symlinks'] == 1
    assert not measure_files(tmp_path, max_entries=1)['complete']

def test_missing_directory_is_unknown(tmp_path):
    result = measure_files(tmp_path / 'missing')
    assert result['bytes'] is None and not result['complete']

def test_module_assignment_and_pg_accounting(auth_client, monkeypatch):
    monkeypatch.setattr(service, 'collector_usage', lambda db: {'status': 'not_configured', 'bytes': None})
    response = auth_client.post(URL + '/measure')
    assert response.status_code == 200, response.text
    value = response.json()
    assert value['database_bytes'] > 0
    assert sum(m['data_bytes'] + m['index_bytes'] for m in value['modules']) == value['database_bytes']
    for name, owner in [('ad_snapshot', 'ad'), ('ksc_host', 'ksc'), ('vm_trend_publication', 'vm'), ('th_intel_item', 'th'), ('snapshot', 'siem'), ('asset', 'assets'), ('radar_server', 'radar'), ('radar_snapshot', 'radar'), ('app_user', 'platform')]:
        assert service.table_module('public', name) == owner
    assert service.table_module('other', 'ad_snapshot') == 'platform'
    assert auth_client.post(URL + '/measure').status_code == 409

def test_storage_permissions(client_as):
    assert client_as({'vm': 'admin'}).get(URL).status_code == 403
    reader = client_as({'platform': 'read'})
    assert reader.get(URL).status_code == 200
    assert reader.post(URL + '/measure').status_code == 403
    assert reader.put('/api/settings/schedules/platform/storage/0', json={'interval_hours': 24}).status_code == 403
    assert client_as({'platform': 'admin'}).get(URL + '?days=999').status_code == 422

def test_schedule_exposed_runs_once_and_can_be_disabled(auth_client, db_session, monkeypatch):
    monkeypatch.setattr(service, 'collector_usage', lambda db: {'status': 'not_configured', 'bytes': None})
    tasks = auth_client.get('/api/settings/schedules').json()['items']
    assert any(t['module'] == 'platform' and t['kind'] == 'storage' for t in tasks)
    response = auth_client.put('/api/settings/schedules/platform/storage/0', json={'interval_hours': 24, 'weekdays': [0, 1, 2, 3, 4, 5, 6], 'run_time': '03:00'})
    assert response.status_code == 200
    when = dt.datetime.fromisoformat(response.json()['next_run_at'])
    assert len(tick(db_session, when)) == 1
    # The common scheduler enqueues work; measurement happens in the queue worker.
    assert db_session.scalar(select(func.count()).select_from(StorageSample)) == 0
    dispatch(db_session)
    deadline = time.monotonic() + 5
    while db_session.scalar(select(func.count()).select_from(StorageSample)) == 0 and time.monotonic() < deadline:
        db_session.rollback()
        time.sleep(0.02)
    assert db_session.scalar(select(func.count()).select_from(StorageSample)) == 1
    assert tick(db_session, when) == []
    assert db_session.scalar(select(func.count()).select_from(StorageSample)) == 1
    assert auth_client.delete('/api/settings/schedules/platform/storage/0').status_code == 204

def test_history_real_points_and_incomplete(auth_client, db_session):
    now = dt.datetime.now(dt.UTC)
    for age, size, complete in [(40, 50, True), (5, 100, True), (2, 180, False), (0, 200, True)]:
        db_session.add(StorageSample(measured_at=now-dt.timedelta(days=age), data={'total_bytes': size, 'complete': complete, 'coverage': 'pg+files', 'modules': []}))
    db_session.commit()
    result = auth_client.get(URL + '?days=7').json()
    assert len(result['history']) == 3
    assert result['latest']['total_bytes'] == 200
    assert result['history'][1]['complete'] is False

def test_collector_unavailable_not_reported_as_zero(auth_client, monkeypatch):
    monkeypatch.setattr(service, 'collector_usage', lambda db: {'status': 'unavailable', 'bytes': None})
    result = auth_client.post(URL + '/measure').json()
    assert result['collector_bytes'] is None and not result['complete']
    assert any(m['id'] == 'collector' and not m['complete'] for m in result['modules'])


def test_measurement_lock_prevents_parallel_work(auth_client, db_session):
    from sqlalchemy import text
    db_session.execute(text("SELECT pg_advisory_xact_lock(hashtext('platform_storage_measure'))"))
    assert auth_client.post(URL + '/measure').status_code == 409
    db_session.rollback()


def test_failed_collector_and_legacy_are_distinct(db_session, monkeypatch):
    from api.modules.vm.services.trends.settings import TrendConnection
    from api.modules.vm.services.trends import settings, client
    monkeypatch.setattr(settings, 'load_connection', lambda db: TrendConnection(url='https://example.org', token='test'))
    monkeypatch.setattr(client.CollectorClient, 'request', lambda *a, **k: {'storage_bytes': 100})
    assert service.collector_usage(db_session) == {'status': 'legacy', 'bytes': 100}
    monkeypatch.setattr(client.CollectorClient, 'request', lambda *a, **k: {'storage': {'database_bytes': 100, 'wal_bytes': 20, 'shm_bytes': 10}})
    assert service.collector_usage(db_session)['bytes'] == 130
    monkeypatch.setattr(client.CollectorClient, 'request', lambda *a, **k: {'storage_bytes': -1})
    assert service.collector_usage(db_session)['status'] == 'unavailable'


def test_retention_and_latest_even_without_recent_points(auth_client, db_session, monkeypatch):
    monkeypatch.setattr(service, 'collector_usage', lambda db: {'status': 'not_configured', 'bytes': None})
    now = dt.datetime.now(dt.UTC)
    db_session.add(StorageSample(measured_at=now-dt.timedelta(days=400), data={'total_bytes': 20, 'complete': True, 'coverage': 'old', 'modules': []}))
    db_session.commit()
    result = auth_client.get(URL + '?days=7').json()
    assert result['latest']['total_bytes'] == 20 and result['history'] == []
    assert auth_client.post(URL + '/measure').status_code == 200
    assert len(list(db_session.scalars(select(StorageSample)))) == 1


def test_history_uses_last_daily_sample_and_caps_retention(auth_client, db_session, monkeypatch):
    monkeypatch.setattr(service, 'collector_usage', lambda db: {'status': 'not_configured', 'bytes': None})
    now = dt.datetime.now(dt.UTC)
    data = {'total_bytes': 20, 'complete': True, 'coverage': 'pg+files', 'modules': []}
    for i in range(1001):
        db_session.add(StorageSample(measured_at=now-dt.timedelta(hours=i+2), data={**data, 'total_bytes': i}))
    db_session.commit()
    assert auth_client.post(URL + '/measure').status_code == 200
    rows = list(db_session.scalars(select(StorageSample).order_by(StorageSample.measured_at)))
    assert len(rows) == 1000
    result = auth_client.get(URL + '?days=365').json()
    from zoneinfo import ZoneInfo
    zone = ZoneInfo(result['tz'])
    expected = {}
    for row in rows:
        expected[row.measured_at.astimezone(zone).date()] = row.data['total_bytes']
    assert [p['total_bytes'] for p in result['history']] == list(expected.values())
