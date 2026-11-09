import pytest
from stools_threat_collector.outbound_profiles import make_fetcher
from stools_threat_collector.monitoring import failure_status
from stools_threat_collector.storage import Store
from stools_threat_collector.catalog import build_catalog_plan,apply_catalog_plan


def test_required_proxy_never_falls_back_direct(monkeypatch):
    monkeypatch.setenv('COLLECTOR_REQUIRE_PROXY','true')
    monkeypatch.delenv('COLLECTOR_HTTP_PROXY',raising=False)
    with pytest.raises(ValueError): make_fetcher({'proxy_profile':'inherit'})
    with pytest.raises(ValueError): make_fetcher({'proxy_profile':'direct'})

def test_system_pause_is_separate_from_enabled():
    result=failure_status({'status':{'failures':4},'enabled':False},ValueError('failure'))
    assert result['system_paused'] and result['failures']==5 and 'enabled' not in result

def test_catalog_rejects_forged_duplicate_add(tmp_path):
    store=Store(tmp_path/'db.sqlite'); source={'name':'one','publisher_id':'example','url':'https://example.org/feed','adapter':'rss'}
    store.save_source(source)
    plan=build_catalog_plan(store.sources(),[source]); plan.rows[0].action='add';plan.rows[0].selected=True
    with pytest.raises(ValueError): apply_catalog_plan(store,plan,plan.expected_revision)
    assert len(store.sources())==1


def test_window_job_preserves_main_checkpoint_and_reports_result(tmp_path,monkeypatch):
    import json
    from stools_threat_collector.scheduler import Runner
    from stools_threat_collector import monitoring
    from stools_threat_collector.collection import ADAPTERS
    from stools_threat_collector.monitoring_contracts import CollectionWindow
    store=Store(tmp_path/'collector.db')
    source=store.save_source({'name':'test','publisher_id':'test','url':'https://example.org/rss'})
    store.ingest(source['id'],[],{'main':'cursor'})
    monkeypatch.setitem(ADAPTERS,'rss',lambda source,cp,fetcher,**kw: ([{'external_id':'one','title':'CVE-2026-12345','url':'https://example.org/a','published_at':'2026-11-06T12:00:00Z'}],{'other':'cursor'}))
    runner=Runner(store)
    job=runner.submit(source['id'],CollectionWindow(date_from='2026-11-01T00:00:00Z',date_to='2026-11-07T00:00:00Z'))
    runner.close()
    assert store.source(source['id'])['checkpoint']=={'main':'cursor'}
    result=monitoring.run(store,job)
    assert result['state']=='succeeded' and result['counters']['new_versions']==1


def test_preview_does_not_ingest_and_bulk_conflict_is_atomic(tmp_path,monkeypatch):
    from fastapi.testclient import TestClient
    from stools_threat_collector.app import create_app
    store=Store(tmp_path/'collector.db')
    token=store.create_token('admin',['data:read','sources:write']);headers={'Authorization':'Bearer '+token}
    source=store.save_source({'name':'test','publisher_id':'test','url':'https://example.org/rss'})
    before=store.info()['last_seq']
    with TestClient(create_app(store,run_scheduler=False)) as client:
        plan=client.post('/api/v1/sources/import/preview',headers=headers,json={'rows':[{'name':'new','publisher_id':'new','url':'https://other.org/feed'}]}).json()
        assert plan['rows'][0]['action']=='add' and store.info()['last_seq']==before
        response=client.post('/api/v1/sources/bulk',headers=headers,json={'items':[{'id':source['id'],'version':999}],'enabled':True})
        assert response.status_code==409 and not store.source(source['id'])['enabled']


def test_cancelled_run_cannot_start_or_ingest(tmp_path):
    from stools_threat_collector import monitoring
    store=Store(tmp_path/'collector.db')
    source=store.save_source({'name':'test','publisher_id':'test','url':'https://example.org/rss'})
    job=store.create_job(source['id'])
    monitoring.update_run(store,job,source_id=source['id'],state='cancelled')
    assert monitoring.update_run(store,job,state='running')['state']=='cancelled'
    before=store.info()['last_seq']
    count=store.ingest(source['id'],[{'external_id':'one','title':'test','url':'https://example.org/a'}],{'done':True},source['version'],job_id=job)
    assert count==0 and store.info()['last_seq']==before and store.source(source['id'])['checkpoint']=={}


def test_resuming_older_job_cannot_rewind_main_cursor(tmp_path,monkeypatch):
    from stools_threat_collector.scheduler import Runner
    from stools_threat_collector import monitoring
    from stools_threat_collector.collection import ADAPTERS
    from stools_threat_collector.monitoring_contracts import CollectionBatch
    store=Store(tmp_path/'collector.db')
    source=store.save_source({'name':'test','publisher_id':'test','url':'https://example.org/rss'})
    monkeypatch.setitem(ADAPTERS,'rss',lambda *a,**kw: CollectionBatch(checkpoint={'position':100},continuation={'position':100}))
    runner=Runner(store);job=runner.submit(source['id']);runner.close()
    store.ingest(source['id'],[],{'position':200})
    monkeypatch.setitem(ADAPTERS,'rss',lambda *a,**kw: CollectionBatch(checkpoint={'position':125}))
    runner=Runner(store);resumed=runner.submit(source['id'],resume=job);runner.close()
    assert monitoring.run(store,resumed)['state']=='succeeded'
    assert store.source(source['id'])['checkpoint']=={'position':200}


def test_poc_worker_consumes_saved_search_page(tmp_path,monkeypatch):
    import json
    from stools_threat_collector.scheduler import Runner
    store=Store(tmp_path/'collector.db');store.enqueue_work('search:CVE-2026-12345','poc_search',{'cve_id':'CVE-2026-12345','continuation':{'page':2}})
    calls=[]
    def search(cve,fetcher,page=1):
        calls.append(page);return {'candidates':[],'continuation':None,'truncated':False,'provider_status':'ok','total':21}
    monkeypatch.setattr('stools_threat_collector.scheduler.search_poc_candidates',search)
    runner=Runner(store);runner.poc_step();runner.close()
    assert calls==[2]
