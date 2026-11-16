import json

import pytest
from sqlalchemy import func, select

from api.modules.vm.models import VmCve, VmHost, VmHostCve, VmRefEpss, VmRefKev, VmRefNvd
from api.modules.vm.trend_models import VmTrendCard

BASE = '/api/vm/cve'
CVE = 'CVE-2026-12345'


def nvd(identifier=CVE, **kw):
    return VmRefNvd(cve_id=identifier, year=2026, description='A remote attacker can read protected data.',
                    cvss_v3=10.0, v3_av='NETWORK', **kw)


def test_reference_only_cve_found_without_inventory_or_trend(auth_client, db_session):
    db_session.add(nvd()); db_session.commit()
    response = auth_client.get(BASE, params={'q': ' cve-2026-12345 '})
    assert response.status_code == 200, response.text
    assert response.json()['items'][0]['id'] == CVE
    detail = auth_client.get(BASE+'/'+CVE).json()
    assert detail['description'].startswith('A remote attacker')
    assert detail['cvss'] == 10 and detail['severity'] == 'critical'
    assert detail['matches']['hosts_total'] == 0
    assert detail['risk']['min'] <= detail['risk']['max']
    assert db_session.scalar(select(func.count()).select_from(VmCve)) == 0
    assert db_session.scalar(select(func.count()).select_from(VmTrendCard)) == 0


def test_potential_range_and_actual_host_risks_are_separate(auth_client, db_session):
    db_session.add_all([nvd(), VmRefKev(cve_id=CVE), VmCve(cve_id=CVE)])
    hosts=[VmHost(hostname='internal',ip='192.0.2.1'), VmHost(hostname='external',ip='192.0.2.2')]
    db_session.add_all(hosts); db_session.flush()
    db_session.add_all([VmHostCve(host_id=hosts[0].id,cve_id=CVE,risk=45), VmHostCve(host_id=hosts[1].id,cve_id=CVE,risk=90)])
    db_session.commit()
    result=auth_client.get(BASE+'/'+CVE).json()
    assert (result['risk']['min'], result['risk']['max']) == (80, 100)
    assert result['known_exploited'] is True
    assert (result['matches']['risk_min'], result['matches']['risk_max']) == (45,90)
    assert result['matches']['hosts_total'] == 2
    assert [h['risk'] for h in result['matches']['hosts']] == [90,45]


def test_zero_and_missing_metrics_not_confused(auth_client, db_session):
    row=nvd(); row.cvss_v3=0
    db_session.add_all([row,VmRefEpss(cve_id=CVE,epss=0,percentile=0)]); db_session.commit()
    data=auth_client.get(BASE+'/'+CVE).json()
    assert data['cvss'] == 0 and data['epss'] == 0
    assert data['known_exploited'] is None
    assert data['risk']['max'] == 37
    assert data['severity'] == 'none'


def test_epss_only_and_missing_cve(auth_client, db_session):
    db_session.add(VmRefEpss(cve_id=CVE,epss=.003,percentile=.5)); db_session.commit()
    data=auth_client.get(BASE+'/'+CVE).json()
    assert data['description'] == '' and data['cvss'] is None
    assert data['epss'] == .003
    assert data['risk']['assumptions']
    assert auth_client.get(BASE+'/CVE-2026-99999').status_code == 404


def test_search_prefix_is_bounded_and_validated(auth_client, db_session):
    db_session.add_all([nvd('CVE-2026-10001'),nvd('CVE-2026-10002'),nvd('CVE-2026-10003')]);db_session.commit()
    first=auth_client.get(BASE,params={'q':'CVE-2026','limit':2}).json()
    assert len(first['items']) == 2 and first['has_more']
    second=auth_client.get(BASE,params={'q':'CVE-2026','limit':2,'offset':2}).json()
    assert len(second['items']) == 1 and not second['has_more']
    assert auth_client.get(BASE,params={'q':'%'}).status_code == 422
    assert auth_client.get(BASE,params={'q':'CVE-2026','limit':1000}).status_code == 422


def test_search_rbac(client,client_as):
    assert client.get(BASE,params={'q':CVE}).status_code == 401
    assert client_as({'vm':'deny'}).get(BASE,params={'q':CVE}).status_code == 403
    assert client_as({'vm':'read'}).get(BASE,params={'q':CVE}).status_code == 200


def test_ai_saved_for_reference_only_cve_and_no_inventory_sent(auth_client,client_as,db_session,monkeypatch):
    from api.modules.vm.services.trends import assistant
    db_session.add_all([nvd(),VmCve(cve_id=CVE),VmHost(hostname='private-host',ip='192.0.2.55')]);db_session.commit()
    auth_client.put('/api/settings/llm',json={'base_url':'http://local:11434','tasks':{'vulnerability_assistant':{'provider':'ollama','model':'explainer'}}})
    calls=[]
    class Completion:
        def __init__(self, config): pass
        def complete(self,prompt,schema):
            calls.append(prompt)
            if 'translation' in schema['properties']:return json.dumps({'translation':'Удалённый атакующий может прочитать защищённые данные.'})
            return json.dumps({'summary':CVE+': чтение данных','danger':'Утечка данных','affected':'Версии не указаны','actions':['Проверить обновления'],'limitations':['Нет сведений о версиях']})
    monkeypatch.setattr(assistant,'OllamaCompletion',Completion)
    url=BASE+'/'+CVE+'/assistant'
    for mode in ['translate','explain']:
        response = auth_client.post(url,json={'mode':mode})
        assert response.status_code == 200, response.text
        assert auth_client.post(url,json={'mode':mode}).json()['cached']
    auditor=client_as({'vm':'read'})
    saved=auditor.get(url).json()
    assert saved['translate']['translation'] and saved['explain']['summary']
    assert len(calls)==2
    assert not any('private-host' in p or '192.0.2.55' in p or 'hostname' in p for p in calls)
    assert auditor.post(url,json={'mode':'translate'}).status_code == 403
    record=db_session.get(VmRefNvd,CVE); record.description='Changed public description'; db_session.commit()
    assert auditor.get(url).json()['translate']['stale']
    assert len(calls)==2
    assert auth_client.post(url,json={'mode':'translate'}).status_code == 200
    assert len(calls)==3


@pytest.mark.parametrize('source', ['kev','exploitdb','msf','attack','vm','harbor','collector'])
def test_search_all_loaded_sources(auth_client,db_session,source):
    from api.modules.vm.models import (
        VmImage,
        VmImageCve,
        VmRefAttack,
        VmRefExploitdbCve,
        VmRefMsfCve,
    )
    from api.modules.vm.trend_models import VmTrendEnrichment, VmTrendIngestState
    if source == 'kev': db_session.add(VmRefKev(cve_id=CVE,name='Known exploited issue'))
    elif source == 'exploitdb': db_session.add(VmRefExploitdbCve(cve_id=CVE,exploit_id=123))
    elif source == 'msf': db_session.add(VmRefMsfCve(cve_id=CVE,fullname='exploit/test'))
    elif source == 'attack': db_session.add(VmRefAttack(cve_id=CVE,technique_id='T1190',mapping_type='exploitation_technique'))
    elif source == 'vm': db_session.add(VmCve(cve_id=CVE,description='Public imported description'))
    elif source == 'harbor':
        image=VmImage(project='test',repository='test',digest='sha256:cve-search')
        db_session.add(image);db_session.flush()
        db_session.add(VmImageCve(image_id=image.id,cve_id=CVE.lower(),package='test',installed_version='1',trivy_severity='high',description='Scanner CVE description'))
    else:
        db_session.add(VmTrendIngestState(id=1,collector_id='test',epoch='e',generation='g',active_generation='g'))
        db_session.add(VmTrendEnrichment(generation='g',external_id='cve:'+CVE,revision=1,data={}))
    db_session.commit()
    assert auth_client.get(BASE,params={'q':CVE}).json()['items'][0]['id'] == CVE
    response=auth_client.get(BASE+'/'+CVE)
    assert response.status_code==200,response.text
    if source=='harbor':
        assert response.json()['severity']=='high'
        assert response.json()['cvss'] is None
        assert response.json()['images_total']==1


def test_host_paging_and_exact_cve_match(auth_client,db_session):
    other='CVE-2026-123456'
    db_session.add_all([VmCve(cve_id=CVE),VmCve(cve_id=other)])
    for i in range(3):
        host=VmHost(hostname=f'host-{i}',ip=f'192.0.2.{i+1}');db_session.add(host);db_session.flush()
        db_session.add(VmHostCve(host_id=host.id,cve_id=other if i==2 else CVE,risk=i*10))
    db_session.commit()
    page=auth_client.get(BASE+'/'+CVE+'/hosts',params={'limit':1,'offset':1}).json()
    assert page['hosts_total']==2 and len(page['hosts'])==1
    assert page['hosts'][0]['hostname']=='host-0'
    assert (page['risk_min'],page['risk_max'])==(0,10)


def test_ksc_matches_use_latest_snapshot_and_keep_evidence_kind(auth_client,db_session):
    import datetime as dt

    from tests.vm.test_ksc_software import entry, seed, snapshot, store
    server=seed(db_session);now=dt.datetime.now(dt.UTC)
    first=snapshot(db_session,server,now-dt.timedelta(days=1));store(db_session,first,entry())
    data=auth_client.get(BASE+'/'+CVE).json()
    assert data['matches']['hosts_total']==0
    assert data['software_matches']['total']==1
    assert data['software_matches']['items'][0]['state']=='affected'
    newest=snapshot(db_session,server,now);store(db_session,newest,entry('3.0'))
    assert auth_client.get(BASE+'/'+CVE).json()['software_matches']['total']==0


def test_legacy_weights_do_not_change_additive_policy(auth_client,db_session):
    from api.db.models import AppSetting
    from api.modules.vm.core.weights import Weights
    weights=Weights().model_dump();weights['reach']['network_internal']=0.1
    db_session.add_all([nvd(),VmRefKev(cve_id=CVE),AppSetting(key='vm',value_json=json.dumps({'weights':weights}))]);db_session.commit()
    data=auth_client.get(BASE+'/'+CVE).json()
    assert (data['risk']['min'],data['risk']['max'])==(80,100)


def test_collector_cvss_v2_preserves_version_and_high_severity(auth_client,db_session):
    from api.modules.vm.trend_models import VmTrendEnrichment, VmTrendIngestState
    vector='AV:N/AC:L/Au:N/C:C/I:C/A:C'
    db_session.add(VmTrendIngestState(id=1,collector_id='test',epoch='e',generation='g',active_generation='g'))
    db_session.add(VmTrendEnrichment(generation='g',external_id='cve:'+CVE,revision=1,data={'cvss':10,'cvss_vector':vector}))
    db_session.commit()
    data=auth_client.get(BASE+'/'+CVE).json()
    assert data['cvss_version']=='2.0'
    assert data['severity']=='high'
    assert data['cvss_vector']==vector


@pytest.mark.parametrize('missing_description', ['', None, '  '])
def test_harbor_description_and_max_severity_are_independent(auth_client,db_session,missing_description):
    from api.modules.vm.models import VmImage, VmImageCve
    for i, (severity,description) in enumerate([('low',missing_description),('critical','Available public CVE description')]):
        image=VmImage(project='test',repository='test',digest=f'sha256:source-{i}')
        db_session.add(image);db_session.flush()
        db_session.add(VmImageCve(image_id=image.id,cve_id=CVE,package='test',installed_version='1',trivy_severity=severity,description=description))
    db_session.commit()
    data=auth_client.get(BASE+'/'+CVE).json()
    assert data['cvss'] is None
    assert data['severity']=='critical'
    assert data['description']=='Available public CVE description'
