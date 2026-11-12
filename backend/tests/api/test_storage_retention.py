import datetime as dt
from sqlalchemy import select, text
URL = '/api/settings/storage/retention'


def test_policy_permissions_and_limits(auth_client, client_as):
    response = auth_client.get(URL)
    assert response.status_code == 200
    policy = response.json()['policy']
    assert policy['receipt_payload_days'] == 14
    assert policy['clear_staging'] is True
    assert response.json()['last_run'] is None
    assert auth_client.put(URL, json={**policy, 'receipt_payload_days': 0}).status_code == 422
    reader = client_as({'platform': 'read'})
    assert reader.get(URL).status_code == 200
    assert reader.post(URL + '/preview').status_code == 403


def test_preview_single_use_policy_binding_and_audit(auth_client):
    preview = auth_client.post(URL + '/preview')
    assert preview.status_code == 200, preview.text
    value = preview.json()
    assert any(i['status'] == 'protected' for i in value['items'])
    policy = auth_client.get(URL).json()['policy']
    assert auth_client.put(URL, json={**policy, 'receipt_payload_days': 15}).status_code == 200
    assert auth_client.post(URL + '/run', json={'preview_id': value['preview_id']}).status_code == 409
    fresh = auth_client.post(URL + '/preview').json()
    result = auth_client.post(URL + '/run', json={'preview_id': fresh['preview_id']})
    assert result.status_code == 200, result.text
    assert auth_client.get(URL).json()['last_run']['finished_at']
    assert auth_client.post(URL + '/run', json={'preview_id': fresh['preview_id']}).status_code == 409


def test_job_retention_and_running_import_protects_staging(auth_client, db_session):
    from api.modules.vm.models import VmJob, VmStageHost
    old = dt.datetime.now(dt.UTC) - dt.timedelta(days=100)
    rows = [VmJob(kind='import_vm', status=status, started_at=old, finished_at=None if status == 'running' else old)
            for status in ('done', 'failed', 'running')]
    db_session.add_all(rows)
    db_session.add(VmStageHost(hostname='active'))
    db_session.commit()
    preview = auth_client.post(URL + '/preview').json()
    result = auth_client.post(URL + '/run', json={'preview_id': preview['preview_id']})
    assert result.status_code == 200, result.text
    db_session.expire_all()
    assert list(db_session.scalars(select(VmJob.status))) == ['running']
    assert db_session.scalar(select(VmStageHost.hostname)) == 'active'
    assert any(i['id'] == 'staging' and i['status'] == 'skipped' for i in result.json()['items'])


def test_cleanup_lock_blocks_parallel_run(auth_client, db_session):
    preview = auth_client.post(URL + '/preview').json()
    db_session.execute(text("SELECT pg_advisory_xact_lock(hashtext('platform_storage_cleanup'))"))
    assert auth_client.post(URL + '/run', json={'preview_id': preview['preview_id']}).status_code == 409
    db_session.rollback()


def test_cleanup_schedule_is_disabled_and_visible(auth_client):
    rows = auth_client.get('/api/settings/schedules').json()['items']
    item = next(i for i in rows if i['module'] == 'platform' and i['kind'] == 'storage_cleanup')
    assert item['schedule'] is None or item['schedule']['enabled'] is False


def test_nonempty_staging_is_protected_even_without_running_job(auth_client, db_session):
    from api.modules.vm.models import VmStageHost
    db_session.add(VmStageHost(hostname='unfinished-import'))
    db_session.commit()
    preview = auth_client.post(URL + '/preview').json()
    result = auth_client.post(URL + '/run', json={'preview_id':preview['preview_id']})
    assert result.status_code == 200
    db_session.expire_all()
    assert db_session.scalar(select(VmStageHost.hostname)) == 'unfinished-import'


def test_expired_preview_cannot_run(auth_client, db_session):
    from api.platform.storage_retention import RetentionPreview
    preview=auth_client.post(URL + '/preview').json()
    row=db_session.get(RetentionPreview,preview['preview_id'])
    row.expires_at=dt.datetime.now(dt.UTC)-dt.timedelta(seconds=1)
    db_session.commit()
    assert auth_client.post(URL+'/run',json={'preview_id':row.id}).status_code==409


def test_scheduler_executes_retention_once(auth_client, db_session):
    from api.platform.scheduler import tick
    from api.platform.storage_retention import RetentionRun
    value=auth_client.put('/api/settings/schedules/platform/storage_cleanup/0',json={'interval_hours':24,'weekdays':[0,1,2,3,4,5,6],'run_time':'03:30'})
    assert value.status_code==200,value.text
    when=dt.datetime.fromisoformat(value.json()['next_run_at'])
    tick(db_session,when)
    db_session.expire_all()
    first=list(db_session.scalars(select(RetentionRun)))
    assert len(first)==1 and first[0].finished_at is not None
    tick(db_session,when)
    assert len(list(db_session.scalars(select(RetentionRun))))==1
