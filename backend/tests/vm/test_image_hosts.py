import datetime as dt

from api.modules.vm.docker_models import VmDockerSnapshot
from api.modules.vm.models import VmImage
from tests.vm.test_docker_inventory import BASE, DIGEST, sample


def test_running_count_deduplicates_asset_and_excludes_stopped(db_session, client_as, tmp_path):
    from api.modules.assets.models import Asset, AssetObservation
    from api.modules.vm.services.docker_inventory import collect_inventory
    from api.modules.vm.services.settings import Connection

    alias = [*BASE]; alias[0] = 'host-a.example (10.0.0.1)'
    stopped = [*BASE]; stopped[0] = 'host-b (10.0.0.2)'

    class Client:
        def export_csv(self, query, path):
            kind = 'containers' if '.Containers.' in query else 'images'
            rows = [BASE, alias, stopped] if kind == 'images' else [
                BASE + ['c1', 'web', 'running', '', '', ''],
                BASE + ['c2', 'worker', 'running', '', '', ''],
                alias + ['c1', 'web', 'running', '', '', ''],
                stopped + ['c3', 'old', 'exited', '', '', ''],
            ]
            path.write_text(sample(kind, rows))

    collect_inventory(db_session, Client(), Connection(host='vm.example', api_token='test'), tmp_path)
    asset = Asset(name='host-a'); db_session.add(asset); db_session.flush()
    for key in ('host-a|10.0.0.1', 'host-a.example|10.0.0.1'):
        db_session.add(AssetObservation(asset_id=asset.id, source='vm', source_key=key, seen_at=dt.datetime.now(dt.UTC)))
    image = VmImage(project='team', repository='app', digest='sha256:'+'b'*64, runtime_ids=[DIGEST])
    db_session.add(image); db_session.commit()
    client = client_as({'vm': 'read', 'assets': 'read'})
    listing = client.get('/api/vm/images').json()
    assert listing['items'][0]['running_host_count'] == 1
    assert client.get(f'/api/vm/images/{image.id}').json()['running_host_count'] == 1
    response = client.get(f'/api/vm/images/{image.id}/hosts')
    assert response.status_code == 200
    data = response.json()
    assert data['total'] == 1 and data['state'] == 'ready'
    assert data['items'][0]['asset_id'] == asset.id
    assert len(data['items'][0]['containers']) == 2
    assert {c['status'] for c in data['items'][0]['containers']} == {'running'}
    assert client.get(f'/api/vm/images/{image.id}/hosts?limit=1&offset=1').json()['items'] == []
    assert client.get(f'/api/vm/images/{image.id}/hosts?limit=0').status_code == 422
    assert client.get(f'/api/assets/container-images?source=harbor&image_id={image.id}').json()['total'] == 1
    assert client.get(f'/api/assets/container-images?source=harbor&image_id={image.id+1000}').json()['total'] == 0
    assert client_as({'assets':'read'}).get(f'/api/vm/images/{image.id}/hosts').status_code == 403


def test_missing_mapping_and_snapshot_are_not_zero(db_session, client_as):
    image = VmImage(project='team', repository='app', digest=DIGEST)
    db_session.add(image); db_session.commit()
    client=client_as({'vm':'read'})
    def view():
        return client.get(f'/api/vm/images/{image.id}/hosts').json()
    assert view()['count'] is None and view()['state'] == 'mapping_missing'
    image.runtime_ids = [DIGEST]; db_session.commit()
    assert view()['count'] is None and view()['state'] == 'snapshot_missing'
    now=dt.datetime.now(dt.UTC)
    db_session.add(VmDockerSnapshot(id=1,source_address='vm.example',attempted_at=now,collected_at=now,error=''))
    db_session.commit()
    assert view()['count'] == 0 and view()['state'] == 'ready'
    snapshot=db_session.get(VmDockerSnapshot,1); snapshot.error='Последний сбор не удался'; db_session.commit()
    assert view()['count']==0 and view()['warning']=='Последний сбор не удался'


def test_harbor_sync_caches_verified_immutable_identity(db_session, monkeypatch):
    from api.modules.vm.core.harbor import HarborClient
    from tests.vm.test_harbor_sync import _images, _sync, fake_harbor
    monkeypatch.setattr(HarborClient,'runtime_image_ids',lambda self,*args:[DIGEST])
    assert _sync(fake_harbor())[0].status=='done'
    assert all(row.runtime_ids==[DIGEST] and row.runtime_checked_at for row in _images(db_session).values())
    def unavailable(*args):
        raise AssertionError('Verified immutable hashes should be reused')
    monkeypatch.setattr(HarborClient,'runtime_image_ids',unavailable)
    assert _sync(fake_harbor())[0].status=='done'
    assert all(row.runtime_ids==[DIGEST] for row in _images(db_session).values())
