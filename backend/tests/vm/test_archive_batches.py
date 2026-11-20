"""Mixed offline archives are durable, serial and rebuild once per batch."""
import pytest
from sqlalchemy import func, select

from api import collector_routes
from api.modules.vm.models import VmCve, VmJob, VmRefState
from api.modules.vm.services import bundle as bundle_service
from api.modules.vm.trend_models import VmTrendPublication
from api.platform.sync_queue import worker
from api.platform.sync_queue.models import SyncStep
from tests.siem_hunting.test_intel import bundle, item
from tests.vm.test_bundle import _fx, _import_hosts, _zip

URL = '/api/vm/refs/batches'


def upload(client, *files):
    return client.post(URL, files=[('files', (name, data, 'application/zip')) for name, data in files])


def run(db, monkeypatch):
    monkeypatch.setattr(collector_routes, 'spawn', lambda work: work())
    worker.dispatch(db)
    worker.dispatch(db)
    db.expire_all()


def test_batch_is_persisted_while_vm_is_busy(client_as, db_session, app_settings):
    client = client_as({'vm': 'admin'})
    db_session.add(VmJob(kind='ref_nvd', status='running'))
    db_session.commit()
    response = upload(client, ('one.zip', _zip({'epss_scores-current.csv': _fx('epss.csv')})))
    assert response.status_code == 202, response.text
    run_id = response.json()['run_id']
    worker.dispatch(db_session)
    step = db_session.scalar(select(SyncStep).where(SyncStep.run_id == run_id))
    assert step.status == 'waiting'
    listing = client.get(URL).json()['items'][0]
    assert listing['run_id'] == run_id and listing['files'][0]['name'] == 'one.zip'
    assert list((app_settings.data_dir / 'vm' / 'archive-batches').glob('*/*.zip'))
    assert db_session.scalar(select(func.count()).select_from(VmRefState)) == 0


def test_mixed_batch_imports_news_and_references_with_one_rebuild(client_as, db_session, monkeypatch, app_settings):
    client = client_as({'vm': 'admin'})
    _import_hosts(client)
    calls = []
    original = bundle_service._rebuild
    def counted(*args, **kwargs):
        calls.append(set(args[2]))
        return original(*args, **kwargs)
    monkeypatch.setattr(bundle_service, '_rebuild', counted)
    response = upload(client,
        ('nvd.zip', _zip({'nvdcve-2.0-2021.json': _fx('nvd-2021.json')})),
        ('epss.zip', _zip({'epss_scores-current.csv': _fx('epss.csv')})),
        ('news.zip', bundle([item(title='Threat CVE-2026-12345')])),
        ('news-2.zip', bundle([item(external_id='article-2', title='Threat CVE-2026-12346')])) )
    assert response.status_code == 202, response.text
    run(db_session, monkeypatch)
    result = client.get(URL).json()['items'][0]
    assert result['status'] == 'done', result
    assert [f['status'] for f in result['files']] == ['done'] * 4
    assert calls == [{'nvd', 'epss'}]
    assert result['rebuild'] == 'done' and result['news_projection'] == 'done'
    assert db_session.scalar(select(func.count()).select_from(VmTrendPublication)) == 2
    assert db_session.get(VmCve, 'CVE-2021-44228').epss > .9
    assert not list((app_settings.data_dir / 'vm' / 'archive-batches').glob('*/*.zip'))


def test_bad_archive_does_not_block_the_remaining_batch(auth_client, db_session, monkeypatch):
    response = upload(auth_client, ('bad.zip', b'not zip'), ('good.zip', _zip({'epss_scores-current.csv': _fx('epss.csv')})))
    assert response.status_code == 202, response.text
    run(db_session, monkeypatch)
    result = auth_client.get(URL).json()['items'][0]
    assert result['status'] == 'partial', result
    assert [f['status'] for f in result['files']] == ['failed', 'done']
    assert result['files'][0]['error'] and result['rebuild'] == 'done'
    assert db_session.get(VmRefState, 'epss').records > 0


@pytest.mark.parametrize('role', ['read', 'write', 'deny'])
def test_batch_requires_vm_admin(client_as, role):
    response = upload(client_as({'vm': role, 'siem': 'admin'}), ('news.zip', bundle()))
    assert response.status_code == 403


def test_cancel_queued_batch_removes_staged_files(auth_client, db_session, app_settings):
    response = upload(auth_client, ('news.zip', bundle()))
    assert response.status_code == 202, response.text
    assert auth_client.post('/api/settings/sync-runs/' + str(response.json()['run_id']) + '/cancel').status_code == 200
    worker.dispatch(db_session)
    from api.modules.vm.services.archive_batches import cleanup
    cleanup(db_session)
    result = auth_client.get(URL).json()['items'][0]
    assert result['status'] == 'cancelled' and result['files'][0]['status'] == 'cancelled'
    assert not list((app_settings.data_dir / 'vm' / 'archive-batches').glob('*/*.zip'))


def test_batch_rejects_foreign_or_traversal_identity(auth_client):
    for batch_id in ('../private', '0' * 32):
        response = auth_client.post('/api/settings/sync-runs', json={'tasks': [
            {'module': 'vm', 'kind': 'archive_import', 'target_id': 0, 'options': {'batch_id': batch_id}}]})
        assert response.status_code in (404, 422)


def test_batch_file_limit_cleans_partial_upload(auth_client, app_settings, monkeypatch):
    from api.modules.vm.services import archive_batches
    monkeypatch.setattr(archive_batches, 'FILE_LIMIT', 10)
    response = upload(auth_client, ('small.zip', b'abcd'), ('too-big.zip', b'x' * 11))
    assert response.status_code == 413
    assert not list((app_settings.data_dir / 'vm' / 'archive-batches').glob('*/*.zip'))


def test_zip_without_recognized_materials_is_an_error(auth_client, db_session, monkeypatch):
    response = upload(auth_client, ('unknown.zip', _zip({'readme.txt': b'not a dataset'})))
    assert response.status_code == 202
    run(db_session, monkeypatch)
    result = auth_client.get(URL).json()['items'][0]
    assert result['status'] == 'failed' and result['files'][0]['status'] == 'failed'


def test_cancel_after_first_file_finishes_its_rebuild(auth_client, db_session, monkeypatch):
    from api.platform.sync_queue.models import SyncRun
    response = upload(auth_client, ('one.zip', _zip({'epss_scores-current.csv': _fx('epss.csv')})),
                      ('two.zip', _zip({'known_exploited_vulnerabilities.json': _fx('kev.json')})))
    assert response.status_code == 202
    original = bundle_service.run_bundle
    def stop_after_first(db, *args, **kwargs):
        original(db, *args, **kwargs)
        db.get(SyncRun, response.json()['run_id']).cancel_requested = True
        db.commit()
    monkeypatch.setattr(bundle_service, 'run_bundle', stop_after_first)
    run(db_session, monkeypatch)
    result = auth_client.get(URL).json()['items'][0]
    assert result['status'] == 'cancelled', result
    assert [entry['status'] for entry in result['files']] == ['done', 'cancelled']
    assert result['rebuild'] == 'done'
    assert db_session.get(VmRefState, 'epss') and not db_session.get(VmRefState, 'kev')


def test_news_projection_runs_once_and_rules_remain_reference_materials(auth_client, db_session, monkeypatch):
    from api.modules.siem.hunting.models import ThHunt, ThIntelItem
    from api.modules.vm.services.trends import news_archive
    calls = []
    original = news_archive.project_news
    def count(db):
        calls.append(1)
        return original(db)
    monkeypatch.setattr(news_archive, 'project_news', count)
    rules = bundle([item(kind='rule', format='sigma', external_id='rule-1')], manifest_change={
        'sources': [{'id': 'test-feed', 'name': 'Rules', 'kind': 'rule', 'url': 'https://example.org/rules', 'status': 'ok', 'items': 1}]})
    response = upload(auth_client, ('news.zip', bundle()), ('news-2.zip', bundle([item(external_id='news-2')])), ('rules.zip', rules))
    assert response.status_code == 202
    run(db_session, monkeypatch)
    result = auth_client.get(URL).json()['items'][0]
    assert result['status'] == 'done', result
    assert calls == [1]
    assert db_session.scalar(select(func.count()).select_from(ThIntelItem).where(ThIntelItem.kind == 'rule')) == 1
    assert db_session.scalar(select(func.count()).select_from(ThHunt)) == 0


def test_revoked_account_cannot_start_saved_batch(auth_client, db_session, monkeypatch, app_settings):
    from api.db.models import AppUser
    from api.modules.vm.services.archive_batches import cleanup
    from api.platform.sync_queue.models import SyncRun
    response = upload(auth_client, ('news.zip', bundle()))
    assert response.status_code == 202
    queued = db_session.get(SyncRun, response.json()['run_id'])
    db_session.get(AppUser, queued.user_id).is_active = False
    db_session.commit()
    run(db_session, monkeypatch)
    cleanup(db_session)
    assert db_session.get(SyncRun, queued.id).status == 'failed'
    assert db_session.scalar(select(func.count()).select_from(VmTrendPublication)) == 0
    assert not list((app_settings.data_dir / 'vm' / 'archive-batches').glob('*/*.zip'))


def test_pending_quota_and_untrusted_filenames(auth_client, app_settings, monkeypatch):
    from api.modules.vm.services import archive_batches
    data = bundle()
    monkeypatch.setattr(archive_batches, 'PENDING_LIMIT', len(data) + 2)
    first = upload(auth_client, ('../../outside.zip', data))
    assert first.status_code == 202
    result = auth_client.get(URL).json()['items'][0]
    assert result['files'][0]['name'] == 'outside.zip'
    assert not (app_settings.data_dir / 'outside.zip').exists()
    assert upload(auth_client, ('another.zip', data)).status_code == 413
    assert len(list((app_settings.data_dir / 'vm' / 'archive-batches').glob('*/*.zip'))) == 1


def test_too_many_files_are_rejected_without_queue_entry(auth_client, db_session):
    response = upload(auth_client, *[(f'{i}.zip', b'zip') for i in range(65)])
    assert response.status_code == 422
    assert db_session.scalar(select(func.count()).select_from(SyncStep).where(SyncStep.key == 'vm/archive_import/0')) == 0


def test_delta_and_full_archives_share_final_rebuild(auth_client, db_session, monkeypatch, tmp_path):
    from api.modules.vm.models import VmRefNvd
    from api.modules.vm.sync_models import VmRefSyncState
    from tests.vm.test_ref_update_import import BASE, TARGET, seed
    from tests.vm.test_ref_update_import import bundle as updates
    seed(db_session, 'nvd', BASE)
    db_session.add(VmRefNvd(cve_id='CVE-2025-1000', year=2025, description='before'))
    db_session.commit()
    path = updates(tmp_path, [{'name': 'nvd', 'mode': 'delta', 'base': BASE, 'target': TARGET,
                              'paths': ['nvd/part.json']}], {
        'nvd/part.json': {'vulnerabilities': [{'cve': {'id': 'CVE-2025-1000',
            'descriptions': [{'lang': 'en', 'value': 'changed'}], 'configurations': []}}]}})
    calls, original = [], bundle_service._rebuild
    def counted(*args, **kwargs):
        calls.append(set(args[2]))
        return original(*args, **kwargs)
    monkeypatch.setattr(bundle_service, '_rebuild', counted)
    response = upload(auth_client, ('updates.zip', path.read_bytes()),
        ('epss.zip', _zip({'epss_scores-current.csv': _fx('epss.csv')})))
    assert response.status_code == 202
    run(db_session, monkeypatch)
    result = auth_client.get(URL).json()['items'][0]
    assert result['status'] == 'done', result
    assert calls == [{'nvd', 'epss'}]
    assert db_session.get(VmRefNvd, 'CVE-2025-1000').description == 'changed'
    assert not db_session.get(VmRefSyncState, 'nvd').pending_rebuild


def test_batch_owner_is_checked_again_at_launch(auth_client, db_session, app_settings, monkeypatch):
    import json
    response = upload(auth_client, ('news.zip', bundle()))
    assert response.status_code == 202
    metadata = next((app_settings.data_dir / 'vm' / 'archive-batches').glob('*/manifest.json'))
    value = json.loads(metadata.read_text())
    value['actor'] = 'different-user'
    metadata.write_text(json.dumps(value))
    run(db_session, monkeypatch)
    result = auth_client.get(URL).json()['items'][0]
    assert result['status'] == 'failed'
    assert db_session.scalar(select(func.count()).select_from(VmTrendPublication)) == 0


def test_concurrent_admission_does_not_wait_on_database_lock(auth_client, db_session):
    from concurrent.futures import ThreadPoolExecutor, TimeoutError

    from sqlalchemy import text
    db_session.execute(text("SELECT pg_advisory_xact_lock(hashtext('vm_archive_upload'))"))
    blocked = False
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(upload, auth_client, ('news.zip', bundle()))
        try:
            response = future.result(timeout=2)
        except TimeoutError:
            blocked = True
        finally:
            db_session.rollback()
        response = future.result(timeout=10)
    assert not blocked, 'Admission waited on the upload lock and can block the async event loop'
    assert response.status_code == 409


def test_completed_zip_can_disappear_during_quota_check(auth_client, app_settings, monkeypatch):
    from pathlib import Path
    first = upload(auth_client, ('first.zip', bundle()))
    assert first.status_code == 202
    victim = next((app_settings.data_dir / 'vm' / 'archive-batches').glob('*/*.zip'))
    original = Path.is_file
    def disappearing(path):
        exists = original(path)
        if path == victim and exists:
            path.unlink()
        return exists
    monkeypatch.setattr(Path, 'is_file', disappearing)
    assert upload(auth_client, ('second.zip', bundle())).status_code == 202


def test_zip_preflight_precedes_format_detection(auth_client, db_session, monkeypatch):
    import zipfile

    from api.modules.vm.core import ref_updates
    payload = bundle()
    response = upload(auth_client, ('news.zip', payload))
    assert response.status_code == 202
    monkeypatch.setattr(ref_updates, 'MAX_FILES', 0)
    allocations = []
    def unexpected(*args, **kwargs):
        allocations.append(True)
        raise AssertionError('ZipFile allocated before bounded preflight')
    monkeypatch.setattr(zipfile, 'ZipFile', unexpected)
    run(db_session, monkeypatch)
    result = auth_client.get(URL).json()['items'][0]
    assert allocations == []
    assert result['files'][0]['status'] == 'failed'
    assert 'числа файлов' in result['files'][0]['error']


@pytest.mark.parametrize('phase', ['rebuild', 'news_projection'])
def test_interrupted_finalization_has_terminal_status(auth_client, db_session, phase):
    from api.platform.sync_queue.models import SyncRun
    response = upload(auth_client, ('news.zip', bundle()))
    assert response.status_code == 202
    queued = db_session.get(SyncRun, response.json()['run_id'])
    queued.status = 'failed'
    job = VmJob(kind='archive_import', status='failed', error='API перезапускался',
                result={'files': [{'name': 'news.zip', 'status': 'done', 'size': 100}], phase: 'running'})
    db_session.add(job)
    db_session.flush()
    step = db_session.scalar(select(SyncStep).where(SyncStep.run_id == queued.id))
    step.job_id, step.job_model, step.status = job.id, 'vm_job', 'failed'
    db_session.commit()
    result = auth_client.get(URL).json()['items'][0]
    assert result['status'] == 'failed' and result[phase] == 'failed'
    assert result['files'][0]['status'] == 'done'
