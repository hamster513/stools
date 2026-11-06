
from api.modules.vm.models import VmImage
from tests.vm.test_docker_inventory import BASE, DIGEST, sample


def test_catalog_sources_filters_rbac_and_unknown_runtime(db_session, client_as, tmp_path):
    from api.modules.vm.services.docker_inventory import collect_inventory
    from api.modules.vm.services.settings import Connection

    class Client:
        def export_csv(self, query, path):
            kind = 'containers' if '.Containers.' in query else 'images'
            path.write_text(sample(kind, [BASE] if kind == 'images' else [BASE + ['c1', 'web', 'running', '', '', '']]))

    collect_inventory(db_session, Client(), Connection(host='vm.example', api_token='test'), tmp_path)
    db_session.add(VmImage(project='team', repository='app', digest=DIGEST, tags='["v1"]', registry_url='https://registry.example'))
    db_session.commit()
    client = client_as({'assets': 'read'})
    response = client.get('/api/assets/container-images')
    assert response.status_code == 200
    data = response.json()
    # Even equal hex strings in different hash namespaces must not be merged.
    assert data['total'] == 2
    harbor = next(r for r in data['items'] if r['source'] == 'harbor')
    assert harbor['status'] == 'unknown' and harbor['host_count'] is None
    assert client.get(f"/api/assets/container-images/harbor/{harbor['id']}").json()['source_address'] == 'https://registry.example'
    assert client.get('/api/assets/container-images?status=running').json()['total'] == 1
    assert client.get('/api/assets/container-images?q=host-a').json()['total'] == 1
    assert client.get('/api/assets/container-images?source=harbor&limit=1').json()['total'] == 1
    item = next(r for r in data['items'] if r['source'] == 'mp_vm')
    detail = client.get(f"/api/assets/container-images/mp_vm/{item['id']}").json()
    assert detail['hosts'][0]['containers'][0]['status'] == 'running'
    assert detail['source_address'] == 'vm.example'
    assert client.get('/api/assets/container-images?status=bad').status_code == 422
    assert client_as({'vm': 'read'}).get('/api/assets/container-images').status_code == 403
