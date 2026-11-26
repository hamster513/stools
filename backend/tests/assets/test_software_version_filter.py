"""Version ranges stay consistent across products, versions and host pages."""
import datetime as dt

import pytest

from api.modules.assets.models import Asset, AssetObservation
from api.modules.ksc.models import KscServer
from tests.assets.test_software_catalog import KEY, product, snapshot
from tests.vm.test_ksc_software import seed


def setup_catalog(db):
    first=seed(db);second=KscServer(name='other KSC');a=Asset(name='shared')
    db.add_all([second,a]);db.flush()
    for server in (first,second):
        db.add(AssetObservation(asset_id=a.id,source='ksc',source_key=f'{server.id}:one',seen_at=dt.datetime.now(dt.UTC)))
    snapshot(db,first,{'old':[product('999.0')]},-1)
    snapshot(db,first,{'one':[product('2.9'),product('2.10.0'),product('2.9-beta'),product('')],
                       'two':[product('10.0'),product('02.010.0')],
                       'three':[product('2.10.0.1'),product('100.0',name='Other Product')]})
    snapshot(db,second,{'one':[product('2.10'),product('2.0')]})


@pytest.mark.parametrize('op,expected,host_count',[('gt',{'10.0','2.10.0.1'},2),('lt',{'2.0','2.9'},1)])
def test_name_and_version_range_apply_to_counts_versions_and_hosts(db_session,client_as,op,expected,host_count):
    setup_catalog(db_session);c=client_as({'assets':'read'})
    filters={'version_op':op,'version_value':'2.10'}
    result=c.get('/api/assets/software/products',params={'q':'Widget',**filters})
    assert result.status_code==200,result.text
    body=result.json();assert body['total']==1
    assert body['items'][0]['version_count']==len(expected) and body['items'][0]['host_count']==host_count
    versions=c.get('/api/assets/software/versions',params={**KEY,**filters}).json()
    assert versions['total']==len(expected) and {v['version'] for v in versions['items']}==expected
    hosts=c.get('/api/assets/software/hosts',params={**KEY,**filters}).json()
    assert hosts['total']==host_count
    assert {v for h in hosts['items'] for v in h['versions']}==expected
    paged=c.get('/api/assets/software/versions',params={**KEY,**filters,'limit':1,'offset':1}).json()
    assert paged['total']==len(expected) and len(paged['items'])==1
    # Choosing a precise version cannot bypass the active range.
    assert c.get('/api/assets/software/hosts',params={**KEY,**filters,'version':'2.10.0'}).json()['total']==0


@pytest.mark.parametrize('threshold',['2.10','02.010.000','2.10.0.0',' 2.10 '])
def test_trailing_zeros_and_leading_zeros_are_equal(db_session,client_as,threshold):
    server=seed(db_session)
    snapshot(db_session,server,{'one':[product('2.10'),product('2.10.0'),product('2.10.0.1')]})
    c=client_as({'assets':'read'})
    for op,expected in [('lt',set()),('gt',{'2.10.0.1'})]:
        out=c.get('/api/assets/software/versions',params={**KEY,'version_op':op,'version_value':threshold})
        assert out.status_code==200,out.text
        assert {v['version'] for v in out.json()['items']}==expected


@pytest.mark.parametrize('filters',[{'version_op':'gt'}, {'version_value':'2.0'}, {'version_op':'eq','version_value':'2.0'},
                                    {'version_op':'lt','version_value':'2.0-beta'}, {'version_op':'lt','version_value':'2..0'},
                                    {'version_op':'lt','version_value':''}, {'version_op':'lt','version_value':'-1.0'},
                                    {'version_op':'gt','version_value':'9'*513}])
def test_invalid_filters_rejected_by_all_endpoints(client_as,filters):
    c=client_as({'assets':'read'})
    for endpoint in ['products','versions','hosts']:
        response=c.get('/api/assets/software/'+endpoint,params={**KEY,**filters})
        assert response.status_code==422,(endpoint,response.text)


def test_uncomparable_and_oversized_versions_do_not_crash_or_match(db_session,client_as):
    server=seed(db_session)
    snapshot(db_session,server,{'one':[product(''),product('not available'),product('1.2-beta'),product('v2.0'),product('9'*600),product('9999999999999999999999999999999999999.2')]})
    c=client_as({'assets':'read'})
    out=c.get('/api/assets/software/versions',params={**KEY,'version_op':'gt','version_value':'2.0'})
    assert out.status_code==200,out.text
    assert [v['version'] for v in out.json()['items']]==['9999999999999999999999999999999999999.2']
    assert c.get('/api/assets/software/versions',params=KEY).json()['total']==6


@pytest.mark.parametrize('op,expected',[('lt',{'0','0.0','0.0.1'}),('gt',{'1.0.0.1','1.1'})])
def test_zero_components_and_integer_threshold(db_session,client_as,op,expected):
    server=seed(db_session)
    snapshot(db_session,server,{'one':[product(v) for v in ['0','0.0','0.0.1','1','1.0.0','1.0.0.1','1.1']]})
    out=client_as({'assets':'read'}).get('/api/assets/software/versions',params={**KEY,'version_op':op,'version_value':'1'})
    assert out.status_code==200,out.text
    assert {v['version'] for v in out.json()['items']}==expected
