import datetime as dt
from types import SimpleNamespace

from sqlalchemy import select

from api.modules.assets.models import Asset, AssetObservation
from api.modules.ksc.models import KscServer, KscSnapshot, KscHost
from api.modules.ksc.services.software import store_inventory
from tests.vm.test_ksc_software import seed


def product(version, publisher="Example", name="Widget"):
    return {"DisplayName": name, "DisplayVersion": version, "Publisher": publisher}


def snapshot(db, server, hosts, days=0):
    snap = KscSnapshot(server_id=server.id, collected_at=dt.datetime.now(dt.UTC)+dt.timedelta(days=days), source="file")
    db.add(snap); db.flush()
    for key in hosts:
        db.add(KscHost(snapshot_id=snap.id, host_id=key, name=key))
    store_inventory(db, snap, SimpleNamespace(hosts=[SimpleNamespace(host_id=k, name=k, os="Windows 11") for k in hosts],
        export=SimpleNamespace(host_inventory={k:{"status":"complete","items":items} for k,items in hosts.items()})))
    db.commit()
    return snap


def fixture(db):
    a=Asset(name="shared-host");b=Asset(name="second-host");db.add_all([a,b]);db.flush()
    s1=seed(db);s2=KscServer(name="second KSC");db.add(s2);db.flush()
    for asset, server, guid in [(a,s1,"one"),(b,s1,"two"),(a,s2,"one")]:
        db.add(AssetObservation(asset_id=asset.id, source="ksc", source_key=f"{server.id}:{guid}", seen_at=dt.datetime.now(dt.UTC)))
    snapshot(db,s1,{"old":[product("0.1",name="Old app")]},-1)
    latest=snapshot(db,s1,{"one":[product("1.9"),product("2.0"),product("1.9",name="Widget 1.9")],
                           "two":[product("2.0"),product("9.0","Other")]})
    snapshot(db,s2,{"one":[product("1.9")],"unmapped":[product("")]})
    return a,b,s1,s2,latest


KEY={"vendor_key":"example","product_key":"widget"}


def test_catalog_groups_versions_and_deduplicates_canonical_hosts(db_session,client_as):
    a,b,s1,s2,snap=fixture(db_session)
    client=client_as({"assets":"read"})
    response=client.get('/api/assets/software/products')
    assert response.status_code==200
    data=response.json()
    assert data['total']==2
    item=next(x for x in data['items'] if x['vendor_key']=='example')
    assert item['version_count']==3 and item['host_count']==3
    assert client.get('/api/assets/software/products',params={'q':'Old app'}).json()['total']==0
    found=client.get('/api/assets/software/products',params={'q':'1.9'}).json()['items'][0]
    assert found['host_count']==3 and found['version_count']==3  # search does not shrink product totals
    assert client.get('/api/assets/software/products',params={'q':'%'}).json()['total']==0
    page=client.get('/api/assets/software/products',params={'limit':1,'offset':1}).json()
    assert page['total']==2 and len(page['items'])==1
    versions=client.get('/api/assets/software/versions',params=KEY).json()
    assert versions['total']==3
    assert {x['version']:x['host_count'] for x in versions['items']}=={'':1,'1.9':1,'2.0':2}
    hosts=client.get('/api/assets/software/hosts',params=KEY).json()
    assert hosts['total']==3
    shared=next(x for x in hosts['items'] if x['asset_id']==a.id)
    assert shared['versions']==['1.9','2.0']
    unknown=client.get('/api/assets/software/hosts',params={**KEY,'version':''}).json()
    assert unknown['total']==1 and unknown['items'][0]['asset_id'] is None
    assert client.get('/api/assets/software/hosts',params={**KEY,'version':'2.0'}).json()['total']==2
    assert len(client.get('/api/assets/software/versions',params={**KEY,'limit':1,'offset':1}).json()['items'])==1
    assert len(client.get('/api/assets/software/hosts',params={**KEY,'limit':1,'offset':1}).json()['items'])==1
    assert client_as({'ksc':'read'}).get('/api/assets/software/products').status_code==403


def test_assets_assessment_checks_source_ownership_and_uses_latest(db_session,client_as):
    a,b,s1,s2,snap=fixture(db_session)
    client=client_as({'assets':'read'})
    url=f'/api/assets/assets/{a.id}/software/assessment'
    response=client.get(url,params={'server_id':s1.id,'host_id':'one'})
    assert response.status_code==200
    data=response.json()
    assert data['snapshot_id']==snap.id and data['coverage']['total']==3
    assert data['finding_counts']['affected']==2
    assert client.get(url,params={'server_id':s1.id,'host_id':'two'}).status_code==404
    assert client.get(url,params={'server_id':s2.id,'host_id':'unmapped'}).status_code==404
    assert client_as({'ksc':'read'}).get(url,params={'server_id':s1.id,'host_id':'one'}).status_code==403
    obs=db_session.scalar(select(AssetObservation).where(AssetObservation.source_key==f'{s1.id}:one'))
    obs.gone_at=dt.datetime.now(dt.UTC);db_session.commit()
    assert client.get(url,params={'server_id':s1.id,'host_id':'one'}).status_code==404
    assert client.get(url,params={'server_id':s2.id,'host_id':'one','limit':101}).status_code==422


def test_new_empty_snapshot_removes_old_installations(db_session,client_as):
    a,b,s1,s2,snap=fixture(db_session)
    snapshot(db_session,s1,{'one':[]},days=1)
    data=client_as({'assets':'read'}).get('/api/assets/software/products').json()
    assert data['total']==1 and data['items'][0]['host_count']==2
    assert data['items'][0]['version_count']==2


def test_missing_versions_unnamed_products_and_unmapped_hosts_stay_distinct(db_session,client_as):
    db=db_session
    a=KscServer(name='A');b=KscServer(name='B');db.add_all([a,b]);db.flush()
    snapshot(db,a,{'same':[product(' \t\n'), product('1',name='')]})
    snapshot(db,b,{'same':[product(''), product('1',name='')]})
    client=client_as({'assets':'read'})
    products=client.get('/api/assets/software/products').json()
    assert products['total']==3  # one Widget, two unrelated unnamed rows
    versions=client.get('/api/assets/software/versions',params=KEY).json()
    assert versions['items']==[{'version':'','host_count':2}]
    hosts=client.get('/api/assets/software/hosts',params={**KEY,'version':''}).json()
    assert hosts['total']==2 and len({item['host_key'] for item in hosts['items']})==2
    av=client_as({'ksc':'read'})
    for path in ['products','versions','hosts']:
        assert av.get(f'/api/assets/software/{path}',params=KEY).status_code==403
        assert client.get(f'/api/assets/software/{path}',params={**KEY,'offset':-1}).status_code==422
