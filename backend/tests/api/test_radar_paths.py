import pytest

from api.modules.assets.models import Asset
from api.modules.radar.models import (
    NettraceConfig,
    NettraceDevice,
    NettraceSnapshot,
    RadarServer,
    RadarSnapshot,
)
from api.modules.radar.parser import parse_dump

BASE = '/api/radar'


def nginx(db, hostname, body):
    server = RadarServer(hostname=hostname)
    db.add(server)
    db.flush()
    snap = RadarSnapshot(server_id=server.id, filename=hostname+'.conf', sha256='test', original_encrypted='not-returned', document=parse_dump(hostname+'.conf', body))
    db.add(snap)
    db.flush()
    server.latest_snapshot_id = snap.id
    db.commit()
    return server, snap


@pytest.fixture
def inventory(db_session):
    db = db_session
    server, snap = nginx(db, 'edge.example', 'http { server { listen 443 ssl; server_name app.example; location / { proxy_pass http://inside.example:8080; } } }')
    internal, inner_snap = nginx(db, 'inside.example', 'http { server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } } }')
    ns = NettraceSnapshot(generation=1, snapshot_set_id='set-0123456789abcdef', snapshot_set={}, device_count=1, warnings=[])
    db.add(ns)
    db.flush()
    cfg = NettraceConfig(id=1, url='https://nt.example', token_encrypted='fixture', ca_pem='', enabled=True, generation=1, latest_snapshot_id=ns.id)
    d = NettraceDevice(snapshot_id=ns.id, device_id='11111111-1111-1111-1111-111111111111', name='external-fw', document={'publications_meta': {'status': 'ok'}, 'rules_meta': {'snapshot': {'id': 'p1'}}, 'rules': [{'id': 'r1', 'service': 'Original'}], 'publications': [{'external': '203.0.113.5', 'internal': '10.0.0.5', 'protocol': 'tcp', 'ports': '443', 'kind': 'static', 'nat_rule_id': 'r1'}]})
    db.add_all([cfg, d])
    db.commit()
    return server, snap, internal, inner_snap, d, cfg


def test_binding_permissions_nat_chain_and_local_application(auth_client, client_as, db_session, inventory):
    server, snap, _internal, inner_snap, device, _ = inventory
    url = f'{BASE}/nginx/servers/{server.id}/addresses'
    assert client_as({'radar': 'read'}).put(url, json={'addresses': ['10.0.0.5']}).status_code == 403
    response = auth_client.put(url, json={'addresses': ['10.0.0.5', '10.0.0.5']})
    assert response.json()['addresses'] == ['10.0.0.5']
    listing = auth_client.get(BASE+'/paths/publications').json()
    assert listing['total'] == 1 and listing['items'][0]['publication_index'] == 0
    assert auth_client.get(BASE+'/paths/publications?q=missing').json()['total'] == 0
    path = auth_client.get(f'{BASE}/paths/publications/{device.id}/0').json()
    assert path['candidate_total'] == 1 and path['candidates'][0]['snapshot_id'] == snap.id
    assert path['candidates'][0]['public_port'] == 443
    selected = auth_client.get(f'{BASE}/paths/nginx/{snap.id}/0?route_index=1').json()
    assert selected['targets'][0]['candidates'][0]['snapshot_id'] == inner_snap.id
    leaf = auth_client.get(f'{BASE}/paths/nginx/{inner_snap.id}/0?route_index=1').json()
    assert leaf['targets'][0]['local'] and leaf['targets'][0]['port'] == 9000
    assert leaf['targets'][0]['candidates'] == []
    assert 'not-returned' not in str(path) + str(selected)
    auth_client.put(url, json={'addresses': []})
    assert auth_client.get(f'{BASE}/paths/publications/{device.id}/0').json()['candidate_total'] == 0


def test_assets_require_permission_and_duplicate_names_do_not_resolve(auth_client, client_as, db_session, inventory):
    _, _, _, _, device, _ = inventory
    db_session.add(Asset(name='edge.example', fqdn='edge.example', ip='10.0.0.5'))
    db_session.commit()
    endpoint = f'{BASE}/paths/publications/{device.id}/0'
    assert client_as({'radar': 'read'}).get(endpoint).json()['candidate_total'] == 0
    both = client_as({'radar': 'read', 'assets': 'read'})
    path = both.get(endpoint).json()
    assert path['candidate_total'] == 1 and path['candidates'][0]['asset']['name'] == 'edge.example'
    db_session.add(Asset(name='duplicate', fqdn='edge.example', ip='10.0.0.6'))
    db_session.commit()
    assert both.get(endpoint).json()['candidate_total'] == 0


def test_old_nettrace_snapshot_rejected_and_nginx_history_labelled(auth_client, db_session, inventory):
    server, snap, _, _, device, cfg = inventory
    newer = RadarSnapshot(server_id=server.id, filename='edge.example.conf', sha256='next', original_encrypted='secret', document=snap.document)
    db_session.add(newer)
    db_session.flush()
    server.latest_snapshot_id = newer.id
    db_session.commit()
    path = auth_client.get(f'{BASE}/paths/nginx/{snap.id}/0').json()
    assert any('исторический' in w for w in path['warnings'])
    cfg.latest_snapshot_id = None
    db_session.commit()
    assert auth_client.get(f'{BASE}/paths/publications/{device.id}/0').status_code == 409


def test_unknown_nat_ports_and_unsupported_sources_stay_explicit(auth_client, db_session, inventory):
    server, _, _, _, device, _ = inventory
    auth_client.put(f'{BASE}/nginx/servers/{server.id}/addresses', json={'addresses': ['10.0.0.5']})
    device.document = {**device.document, 'publications': [{**device.document['publications'][0], 'kind': 'port_forward'}]}
    db_session.commit()
    path = auth_client.get(f'{BASE}/paths/publications/{device.id}/0').json()
    assert path['candidates'][0]['public_port'] is None and any('Порт после NAT' in w for w in path['warnings'])
    device.document = {**device.document, 'publications_meta': {'status': 'no_topology'}, 'publications': []}
    db_session.commit()
    listing = auth_client.get(BASE+'/paths/publications').json()
    assert listing['total'] == 0 and listing['incomplete_devices'] == 1


@pytest.mark.parametrize('address', ['0.0.0.0', '0.1.2.3', '127.0.0.1', '::1', '10.0.0.0/24', '224.0.0.1'])
def test_binding_rejects_unknown_or_non_host_addresses(auth_client, inventory, address):
    server = inventory[0]
    assert auth_client.put(f'{BASE}/nginx/servers/{server.id}/addresses', json={'addresses': [address]}).status_code == 422


def test_non_http_and_tls_mismatch_do_not_join_nginx_and_internal_is_labelled(auth_client, db_session, inventory):
    _server, _snap, _internal, inner_snap, _device, _cfg = inventory
    _, fastcgi = nginx(db_session, 'fastcgi.example', 'http { server { listen 80; location / { fastcgi_pass inside.example:8080; } } }')
    assert auth_client.get(f'{BASE}/paths/nginx/{fastcgi.id}/0').json()['targets'][0]['candidates'] == []
    _, tls = nginx(db_session, 'tls.example', 'http { server { listen 80; location / { internal; proxy_pass https://inside.example:8080; } } }')
    response = auth_client.get(f'{BASE}/paths/nginx/{tls.id}/0').json()
    assert response['targets'][0]['candidates'] == []
    assert any('internal' in w for w in response['warnings'])
    _, plain = nginx(db_session, 'plain.example', 'http { server { listen 80; location / { proxy_pass http://inside.example:8080; } } }')
    assert auth_client.get(f'{BASE}/paths/nginx/{plain.id}/0').json()['targets'][0]['candidates'][0]['snapshot_id'] == inner_snap.id
