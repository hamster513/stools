import pytest

from api.modules.vm.models import VmImage, VmImageCve

BASE='/api/vm/cve'
GHSA='GHSA-2345-6789-cfgh'
CVE='CVE-2025-12345'


def test_lookup_existing_ghsa_finding_without_cve(auth_client,db_session):
    image=VmImage(project='test',repository='app',digest='sha256:ghsa-only')
    db_session.add(image);db_session.flush()
    db_session.add(VmImageCve(image_id=image.id,cve_id=GHSA,package='example',installed_version='1.0.0',trivy_severity='high',trivy_cvss=8.1,description='An issue without a CVE.'))
    db_session.commit()
    result=auth_client.get(BASE+'/'+GHSA)
    assert result.status_code==200,result.text
    detail=result.json()
    assert detail['id']==GHSA
    assert detail['cvss']==8.1
    assert detail['primary_url']=='https://github.com/advisories/'+GHSA
    assert detail['images_total']==1
    assert auth_client.get(BASE,params={'q':GHSA.upper()}).json()['items'][0]['id']==GHSA


def advisory(db,*,alias=None,withdrawn=None):
    from api.modules.vm.ghsa_models import VmRefGhsa, VmRefGhsaAlias, VmRefGhsaPackage
    row=VmRefGhsa(ghsa_id=GHSA,summary='Public package issue',description='A package security vulnerability.',cvss=8.1,cvss_version='3.1',cvss_vector='CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',severity='high',reviewed=True,withdrawn=withdrawn)
    db.add(row);db.flush()
    if alias:db.add(VmRefGhsaAlias(ghsa_id=GHSA,alias=alias))
    db.add(VmRefGhsaPackage(ghsa_id=GHSA,position=0,ecosystem='npm',name='example',purl='pkg:npm/example',ranges=[{'type':'SEMVER','events':[{'introduced':'0'},{'fixed':'1.2.3'}]}],versions=[],fixed_versions=['1.2.3']))
    db.commit()
    return row


def test_ghsa_catalog_only_and_package_metadata(auth_client,db_session):
    from api.modules.vm.models import VmRefState
    advisory(db_session);db_session.add(VmRefState(name='kev'));db_session.commit()
    data=auth_client.get(BASE+'/'+GHSA).json()
    assert data['description']=='A package security vulnerability.'
    assert data['cvss']==8.1 and data['cvss_source']=='ghsa'
    assert data['epss'] is None and data['known_exploited'] is None
    assert data['matches']['hosts_total']==0
    assert data['advisories'][0]['reviewed'] is True
    assert data['packages'][0]['ecosystem']=='npm'
    assert data['packages'][0]['fixed_versions']==['1.2.3']
    assert auth_client.get(BASE,params={'q':'ghsa-2345'}).json()['items'][0]['id']==GHSA


def test_alias_lookup_deduplicates_hosts_images_and_uses_cve_evidence(auth_client,db_session):
    from api.modules.vm.models import VmCve, VmHost, VmHostCve, VmRefEpss, VmRefKev, VmRefNvd
    advisory(db_session,alias=CVE)
    host=VmHost(hostname='test-host');image=VmImage(project='test',repository='app',digest='sha256:aliases')
    db_session.add_all([host,image,VmCve(cve_id=CVE),VmCve(cve_id=GHSA),VmRefNvd(cve_id=CVE,year=2025,cvss_v3=9.8,description='NVD description',v3_av='NETWORK'),VmRefEpss(cve_id=CVE,epss=0.5,percentile=0.9),VmRefKev(cve_id=CVE)]);db_session.flush()
    for key,score in ((CVE,80),(GHSA,70)):
        db_session.add(VmHostCve(host_id=host.id,cve_id=key,risk=score))
        db_session.add(VmImageCve(image_id=image.id,cve_id=key,package='example',installed_version='1.0.0',trivy_severity='critical',risk=score))
    db_session.commit()
    for key in (CVE,GHSA):
        data=auth_client.get(BASE+'/'+key).json()
        assert data['cvss']==9.8 and data['epss']==0.5 and data['known_exploited'] is True
        assert data['matches']['hosts_total']==1
        assert data['matches']['hosts'][0]['risk']==80
        assert data['images_total']==1
        assert data['images']['items'][0]['identifiers']==sorted([CVE,GHSA])
    assert auth_client.get(BASE,params={'q':CVE}).json()['items'][0]['id']==CVE


def test_withdrawn_ghsa_visible_but_not_inferred_as_cve_finding(auth_client,db_session):
    import datetime as dt

    from api.modules.vm.models import VmCve, VmHost, VmHostCve
    advisory(db_session,alias=CVE,withdrawn=dt.datetime.now(dt.UTC))
    host=VmHost(hostname='test');db_session.add_all([host,VmCve(cve_id=CVE)]);db_session.flush()
    db_session.add(VmHostCve(host_id=host.id,cve_id=CVE,risk=20));db_session.commit()
    data=auth_client.get(BASE+'/'+GHSA).json()
    assert data['withdrawn'] is not None
    assert data['cvss']==8.1 and data['cvss_version']=='3.1'
    assert data['cvss_vector'].startswith('CVSS:3.1/')
    assert CVE in data['aliases']
    assert data['matches']['hosts_total']==0


def test_ghsa_assistant_uses_public_context_and_persisted_cache(auth_client,db_session,monkeypatch):
    from api.modules.vm.services import cve_assistant
    advisory(db_session)
    calls=[]
    def generate(db,key,request,original):
        calls.append(original)
        return {'mode':request.mode,'translation':'Перевод GHSA','summary':'Объяснение GHSA','sources':original['sources'],'provider':'test','model':'test','generated_at':'2026-11-14T00:00:00Z','truncated':False}
    monkeypatch.setattr(cve_assistant,'generate',generate)
    for mode in ('translate','explain'):
        response=auth_client.post(BASE+'/'+GHSA+'/assistant',json={'mode':mode})
        assert response.status_code==200,response.text
    saved=auth_client.get(BASE+'/'+GHSA+'/assistant').json()
    assert saved['translate']['translation']=='Перевод GHSA'
    assert saved['explain']['summary']=='Объяснение GHSA'
    assert len(calls)==2 and calls[0]['content']['identifier']==GHSA
    assert calls[0]['sources'][0]['url']=='https://github.com/advisories/'+GHSA


@pytest.mark.parametrize('correct', [True, False])
def test_ghsa_explanation_keeps_its_identifier(auth_client,db_session,monkeypatch,correct):
    import json

    from api.modules.vm.services.trends import assistant
    advisory(db_session)
    auth_client.put('/api/settings/llm',json={'base_url':'http://local:11434','tasks':{'vulnerability_assistant':{'provider':'ollama','model':'explainer'}}})
    class Completion:
        def __init__(self,config):pass
        def complete(self,prompt,schema):
            return json.dumps({'summary':(GHSA if correct else 'GHSA-cccc-gggg-jjjj')+': проблема пакета','danger':'Утечка данных','affected':'Пакет example','actions':['Установить исправление'],'limitations':['Наличие пакета на хостах не подтверждено']})
    monkeypatch.setattr(assistant,'OllamaCompletion',Completion)
    response=auth_client.post(BASE+'/'+GHSA+'/assistant',json={'mode':'explain'})
    assert response.status_code==(200 if correct else 502),response.text
