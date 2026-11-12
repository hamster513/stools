from fastapi.testclient import TestClient
from stools_threat_collector.app import create_app
from stools_threat_collector.storage import Store


def test_api_auth_scopes_and_frozen_pages(tmp_path):
    store = Store(tmp_path / "collector.db")
    reader = store.create_token("reader", ["data:read"])
    admin = store.create_token("admin", ["data:read", "sources:write"])
    with TestClient(create_app(store, run_scheduler=False)) as client:
        assert client.get('/api/v1/info').status_code == 401
        headers = {"Authorization": "Bearer " + reader}
        assert client.get('/api/v1/info', headers=headers).json()['protocol_version'] == 1
        body = {"name": "Test", "publisher_id": "test", "url": "https://example.org/rss"}
        assert client.post('/api/v1/sources', headers=headers, json=body).status_code == 403
        write = {"Authorization": "Bearer " + admin}
        source = client.post('/api/v1/sources', headers=write, json=body).json()
        assert "checkpoint" not in source
        assert client.patch('/api/v1/sources/' + source['id'], headers=write,
                            json={**body, 'version': 9}).status_code == 409
        page = client.get('/api/v1/changes?after=0&limit=1', headers=headers).json()
        assert page['next_cursor'] == page['until_seq'] == 1
        assert client.get('/api/v1/changes?after=99', headers=headers).status_code == 409
        store.revoke_token('reader')
        assert client.get('/api/v1/info', headers=headers).status_code == 401


def test_recovery_releases_abandoned_job(tmp_path):
    store = Store(tmp_path / 'collector.db')
    source = store.save_source({'name': 'Test', 'publisher_id': 'test', 'url': 'https://example.org/rss'})
    job = store.create_job(source['id'])
    store.recover_jobs()
    assert store.job(job)['state'] == 'failed'
    assert store.create_job(source['id']) != job


def test_info_storage_includes_sqlite_sidecars(tmp_path):
    store = Store(tmp_path / 'collector.db')
    token = store.create_token('reader', ['data:read'])
    with TestClient(create_app(store, run_scheduler=False)) as client:
        response = client.get('/api/v1/info', headers={'Authorization': 'Bearer ' + token})
        assert response.status_code == 200
        value = response.json()
        assert value['storage']['database_bytes'] == value['storage_bytes'] > 0
        assert set(value['storage']) == {'database_bytes', 'wal_bytes', 'shm_bytes'}
        assert all(type(n) is int and n >= 0 for n in value['storage'].values())
        assert client.get('/api/v1/info').status_code == 401
