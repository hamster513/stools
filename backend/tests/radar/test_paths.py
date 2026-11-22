from api.modules.radar.paths import match_sites, nat_candidates, parse_listener


def catalog():
    return [{'snapshot_id': 1, 'server_id': 1, 'hostname': 'proxy.example', 'imported_at': 'now',
             'addresses': [{'ip': '10.0.0.5', 'source': 'manual'}], 'asset': None,
             'sites': [{'names': ['app.example'], 'listen': ['443 ssl', '80'], 'routes': []}]}]


def test_listener_requires_known_ipv4_and_explicit_port():
    assert parse_listener('443 ssl')['ip'] is None
    assert parse_listener('10.0.0.5:8443 ssl')['port'] == 8443
    for value in ('[::]:443 ssl', 'unix:/run/nginx.sock', 'host.example:80', '443 quic', '', '65536', '10.0.0.5'):
        assert parse_listener(value) is None


def test_matching_and_no_short_name_guess():
    rows = catalog()
    assert len(match_sites(rows, '10.0.0.5', 443)) == 1
    assert not match_sites(rows, '10.0.0.6', 443)
    assert not match_sites(rows, 'proxy', 443, allow_name=True)
    assert match_sites(rows, 'proxy.example', 443, allow_name=True)[0]['evidence'] == 'name'
    rows[0]['addresses'] = []
    assert not match_sites(rows, '10.0.0.5', 443)
    rows[0]['sites'][0]['listen'] = ['10.0.0.5:443 ssl']
    assert match_sites(rows, '10.0.0.5', 443)[0]['evidence'] == 'listen'


def test_nat_ports_never_invent_translated_port():
    pub = {'external': '203.0.113.5', 'internal': '10.0.0.5', 'protocol': 'tcp', 'ports': '443', 'kind': 'static'}
    items, warnings = nat_candidates(catalog(), pub, {'service': 'Original'})
    assert len(items) == 1 and items[0]['public_port'] == 443 and not warnings
    items, warnings = nat_candidates(catalog(), {**pub, 'kind': 'port_forward'}, {'service': 'tcp/443 -> tcp/8443'})
    assert len(items) == 2 and all(i['public_port'] is None for i in items) and warnings
    assert not nat_candidates(catalog(), {**pub, 'protocol': 'udp'}, {'service': 'Original'})[0]
    assert nat_candidates(catalog(), {**pub, 'ports': 'https'}, {'service': 'Original'})[1]


def test_all_virtual_servers_and_duplicate_bindings_remain_alternatives():
    rows = catalog()
    rows[0]['sites'].append({'names': ['other.example'], 'listen': ['443 ssl']})
    rows.append({**rows[0], 'snapshot_id': 2, 'server_id': 2, 'hostname': 'other-proxy.example'})
    assert len(match_sites(rows, '10.0.0.5', 443)) == 4


def test_loopback_scope_is_never_guessed_from_hostname():
    from api.modules.radar.paths import target_candidates
    rows = catalog()
    rows[0]['sites'][0]['listen'] = ['127.0.0.1:9000', '10.0.0.5:9001', '9002']
    assert not match_sites(rows, 'proxy.example', 9000, allow_name=True)
    local = {'host': 'proxy.example', 'address': 'http://127.0.0.1:9000', 'port': 9000, 'local': True}
    assert len(target_candidates(rows, local, 'proxy.example')) == 1
    assert not target_candidates(rows, {**local, 'port': 9001, 'address': 'http://127.0.0.1:9001'}, 'proxy.example')
    assert len(target_candidates(rows, {**local, 'port': 9002, 'address': 'http://127.0.0.1:9002'}, 'proxy.example')) == 1
    assert not target_candidates(rows, local, 'another.example')
    assert not target_candidates(rows, {**local, 'address': 'http://localhost:9000'}, 'proxy.example')
    assert not target_candidates(rows, {**local, 'address': 'unix:/run/app.sock', 'port': None}, 'proxy.example')


def test_transport_is_filtered_before_deduplicating_same_site_port():
    from api.modules.radar.paths import target_candidates
    rows = catalog()
    rows[0]['sites'][0]['listen'] = ['10.0.0.5:8443', '10.0.0.6:8443 ssl']
    target = {'host': 'proxy.example', 'port': 8443, 'address': 'https://proxy.example:8443', 'local': False}
    tls = target_candidates(rows, target, 'outside.example', tls=True)
    assert len(tls) == 1 and tls[0]['listen'] == '10.0.0.6:8443 ssl'
    plain = target_candidates(rows, target, 'outside.example', tls=False)
    assert len(plain) == 1 and plain[0]['listen'] == '10.0.0.5:8443'
