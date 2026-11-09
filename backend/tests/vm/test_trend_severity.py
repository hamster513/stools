import pytest
from api.modules.vm.services.trends.ingest import apply_page
from api.modules.vm.services.trends.analyze import process_pending
from api.modules.vm.trend_models import VmTrendEnrichment, VmTrendIngestState
from api.modules.vm.models import VmCve, VmRefNvd
from tests.vm.test_trends_api import news_page


def test_list_and_detail_expose_cvss_with_source_and_zero(auth_client, db_session):
    ids = ['CVE-2026-54321', 'CVE-2026-54322', 'CVE-2026-54323', 'CVE-2026-54324']
    apply_page(db_session, news_page([{'identifiers': [cve], 'title': cve} for cve in ids]))
    process_pending(db_session)
    state = db_session.get(VmTrendIngestState, 1)
    db_session.add(VmTrendEnrichment(generation=state.active_generation, external_id='cve:'+ids[0], revision=1,
        data={'cve_id':ids[0], 'cvss':9.8, 'cvss_vector':'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'provenance':{'cvss':'nvd'}}))
    db_session.add(VmRefNvd(cve_id=ids[1],year=2026,cvss_v3=7.5))
    db_session.add(VmCve(cve_id=ids[2],cvss=0.0,cvss_source='nvd_v3'))
    db_session.commit()
    rows = {r['id']:r for r in auth_client.get('/api/vm/trends?view=mentions').json()['items']}
    for cve,score,severity in zip(ids,[9.8,7.5,0.0,None],['critical','high','none','unknown']):
        assert rows[cve]['cvss'] == score
        assert rows[cve]['severity'] == severity
        detail = auth_client.get('/api/vm/trends/'+cve).json()
        assert (detail['cvss'],detail['severity'],detail['cvss_source']) == (score,severity,rows[cve]['cvss_source'])
    assert rows[ids[0]]['cvss_source'] == 'collector_nvd'
    assert rows[ids[1]]['cvss_source'] == 'nvd_v3'


@pytest.mark.parametrize('score,version,expected',[(0,'3.1','none'),(3.9,'3.1','low'),(4,'3.1','medium'),(7,'3.1','high'),(9,'3.1','critical'),(9.8,'2.0','high'),(0,'2.0','low'),(None,'3.1','unknown')])
def test_cvss_severity_thresholds(score,version,expected):
    from api.modules.vm.services.trends.severity import severity_level
    assert severity_level(score,version) == expected


def test_trivy_label_without_score_is_not_local_risk(db_session):
    from api.modules.vm.models import VmImage, VmImageCve
    from api.modules.vm.services.trends.severity import card_severities
    image = VmImage(project='registry', repository='app', digest='sha256:severity-test')
    db_session.add(image); db_session.flush()
    db_session.add(VmImageCve(image_id=image.id,cve_id='ghsa-abcd-efgh-2345',package='app',installed_version='1',trivy_severity='high',risk=99))
    db_session.flush()
    value = card_severities(db_session,['GHSA-ABCD-EFGH-2345'],'none')['GHSA-ABCD-EFGH-2345']
    assert value['severity']=='high' and value['cvss'] is None and value['cvss_source']=='trivy'


def test_retracted_enrichment_falls_back_to_local_reference(db_session):
    from api.modules.vm.services.trends.severity import card_severities
    cve='CVE-2026-76543'
    db_session.add(VmTrendEnrichment(generation='g',external_id='cve:'+cve,revision=2,data={'cvss':10},retracted=True))
    db_session.add(VmRefNvd(cve_id=cve,year=2026,cvss_v3=4.3));db_session.flush()
    value=card_severities(db_session,[cve],'g')[cve]
    assert value['cvss']==4.3 and value['severity']=='medium' and value['cvss_source']=='nvd_v3'
