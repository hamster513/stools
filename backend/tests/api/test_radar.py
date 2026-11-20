from sqlalchemy import select

from api.modules.radar.models import RadarSnapshot

CONFIG = b'http { server { listen 443 ssl; server_name demo.example; location / { proxy_pass http://localhost:8080; } } }'


def upload(client, endpoint='import', data=CONFIG, name='edge.example.conf'):
    return client.post('/api/radar/nginx/' + endpoint, files=[('files', (name, data, 'text/plain'))])


def test_radar_preview_save_history_encryption(client_as, db_session):
    client = client_as({'radar': 'write'})
    preview = upload(client, 'preview')
    assert preview.status_code == 200
    assert preview.json()['items'][0]['document']['hostname'] == 'edge.example'
    assert client.get('/api/radar/nginx/servers').json()['total'] == 0
    first = upload(client).json()['items'][0]
    assert first['unchanged'] is False
    assert upload(client).json()['items'][0]['unchanged'] is True
    changed = upload(client, data=CONFIG.replace(b'8080', b'8081')).json()['items'][0]
    assert changed['id'] != first['id']
    assert len(client.get(f'/api/radar/nginx/servers/{first["server_id"]}/snapshots').json()['items']) == 2
    detail = client.get(f'/api/radar/nginx/snapshots/{first["id"]}').json()
    assert detail['document']['servers'][0]['routes'][1]['targets'][0]['port'] == 8080
    assert 'original_encrypted' not in detail
    row = db_session.scalar(select(RadarSnapshot).where(RadarSnapshot.id == first['id']).limit(1))
    assert row.original_encrypted.startswith('enc:v1:')
    assert client.get('/api/radar/nginx/servers?q=demo.example').json()['total'] == 1
    assert client.get('/api/radar/nginx/servers?q=absent').json()['total'] == 0


def test_radar_bad_batch_is_atomic_and_preserves_previous(client_as):
    client = client_as({'radar': 'write'})
    old = upload(client).json()['items'][0]
    files = [('files', ('new.conf', CONFIG, 'text/plain')), ('files', ('bad.conf', b'http {', 'text/plain'))]
    preview = client.post('/api/radar/nginx/preview', files=files).json()['items']
    assert preview[0]['error'] is None and preview[1]['error']
    assert client.post('/api/radar/nginx/import', files=files).status_code == 422
    latest = client.get('/api/radar/nginx/servers').json()
    assert latest['total'] == 1 and latest['items'][0]['id'] == old['id']


def test_radar_rights(client_as):
    denied = client_as({})
    assert denied.get('/api/radar/nginx/servers').status_code == 403
    assert upload(denied, 'preview').status_code == 403
    reader = client_as({'radar': 'read'})
    assert reader.get('/api/radar/nginx/servers').status_code == 200
    assert upload(reader).status_code == 403
    assert upload(reader, 'preview').status_code == 403
    assert reader.get('/api/radar/nginx/snapshots/9999999').status_code == 404


def test_radar_limits_and_no_secret_echo(client_as):
    client = client_as({'radar': 'write'})
    data = b'http { server { proxy_set_header Authorization "Bearer private-value"; location / { proxy_pass http://u:pw@backend:80/a?key=private-value; } } }'
    response = upload(client, 'preview', data=data)
    assert response.status_code == 200
    assert 'private-value' not in response.text and 'u:pw' not in response.text
    assert upload(client, 'preview', data=b'x'*(2*1024*1024+1)).json()['items'][0]['error']
    files = [('files', ('a.conf', CONFIG, 'text/plain'))]*33
    assert client.post('/api/radar/nginx/preview', files=files).status_code == 422
