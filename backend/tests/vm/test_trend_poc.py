import datetime as dt
from api.modules.vm.services.trends.ingest import apply_page
from api.modules.vm.services.trends.analyze import process_pending
from api.modules.vm.trend_models import VmTrendIngestState, VmTrendPoc
from tests.vm.test_trend_sync import page

ID='poc:CVE-2026-12345:12'
def seed(db):
    apply_page(db,page()); process_pending(db)
    state=db.get(VmTrendIngestState,1)
    row=VmTrendPoc(generation=state.active_generation,external_id=ID,revision=1,
        data={'cve_id':'CVE-2026-12345','repository_id':12,'url':'https://github.com/test/repo','commit_sha':'a'*40,'state':'likely'})
    db.add(row); db.commit(); return row

def test_confirmation_requires_reason_evidence_and_version(auth_client,db_session):
    seed(db_session)
    url='/api/vm/trends/poc/'+ID+'/review'
    assert auth_client.post(url,json={'commit_sha':'a'*40,'version':0,'state':'confirmed','reason':'tested'}).status_code==422
    payload={'commit_sha':'a'*40,'version':0,'state':'confirmed','reason':'Проверено аналитиком','evidence':['https://example.org/report']}
    assert auth_client.post(url,json=payload).status_code==200
    assert auth_client.post(url,json=payload).status_code==409
    result=auth_client.get('/api/vm/trends/CVE-2026-12345').json()
    assert result['pocs'][0]['effective_state']=='confirmed'

def test_new_sha_requires_recheck(auth_client,db_session):
    row=seed(db_session)
    auth_client.post('/api/vm/trends/poc/'+ID+'/review',json={'commit_sha':'a'*40,'version':0,'state':'confirmed','reason':'Проверено аналитиком','evidence':['https://example.org/report']})
    row.data={**row.data,'commit_sha':'b'*40}; db_session.commit()
    result=auth_client.get('/api/vm/trends/CVE-2026-12345').json()['pocs'][0]
    assert result['effective_state']=='likely' and result['needs_recheck']

def test_only_writer_can_review(client_as):
    assert client_as('auditor').post('/api/vm/trends/poc/'+ID+'/review',json={}).status_code==403

def test_expired_policy_restores_visibility(auth_client,db_session):
    seed(db_session)
    url='/api/vm/trends/policies'
    result=auth_client.post(url,json={'scope':'publication','target_key':'pub-1','reason':'Не относится к инфраструктуре','expires_at':(dt.datetime.now(dt.UTC)-dt.timedelta(seconds=1)).isoformat()})
    assert result.status_code==200
    policy=result.json(); assert not policy['active']
    assert auth_client.patch(url+'/'+str(policy['id']),json={'scope':'publication','target_key':'pub-1','reason':'Включено снова','version':999}).status_code==409
