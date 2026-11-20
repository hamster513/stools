import pytest

from api.modules.radar.parser import ParseError, parse_dump


def test_dump_includes_and_local_services():
    result = parse_dump('app.example.conf', '''nginx: configuration is ok
# configuration file /etc/nginx/nginx.conf:
http { include conf.d/*.conf; }
# configuration file /etc/nginx/conf.d/site.conf:
server { include ip/listen.conf; server_name demo.example;
location /api { proxy_pass http://localhost:8080/api; }
location / { root /srv/www; } }
# configuration file /etc/nginx/ip/listen.conf:
listen 10.0.0.5:443 ssl;
'''.replace('\n', '\r\r\n'))
    assert result['hostname'] == 'app.example'
    site = result['servers'][0]
    assert site['listen'] == ['10.0.0.5:443 ssl']
    route = next(r for r in site['routes'] if r['match'] == '/api')
    assert route['targets'][0]['host'] == 'app.example'
    assert route['targets'][0]['port'] == 8080
    assert route['targets'][0]['local'] is True
    assert site['exposure'] == 'unknown'


def test_upstream_members_and_access_inheritance():
    result = parse_dump('gw.conf', '''http {
upstream pool { server backend-a:443; server backend-b:8443 backup; }
server { listen 443 ssl; allow 10.0.0.0/8; deny all;
location / { proxy_pass https://pool/; }
location /open { allow all; proxy_pass https://pool/; }
}}''')
    routes = result['servers'][0]['routes']
    route = next(r for r in routes if r['match'] == '/')
    assert [t['host'] for t in route['targets']] == ['backend-a', 'backend-b']
    assert [s['value'] for s in route['settings'] if s['name'] in ('allow', 'deny')] == ['10.0.0.0/8', 'all']
    route = next(r for r in routes if r['match'] == '/open')
    assert [s['value'] for s in route['settings'] if s['name'] in ('allow', 'deny')] == ['all']


def test_quotes_comments_variables_and_hidden_secrets():
    result = parse_dump('edge.conf', '''http { server { listen 80;
# proxy_pass http://wrong;
set $secret "do-not-leak";
proxy_set_header Authorization "Bearer do-not-leak";
location ~ "^/a{1,3}#b$" { proxy_pass http://${backend}/; }
location /private { proxy_pass http://user:password@backend:8080/path?token=secret; }
}}''')
    assert 'do-not-leak' not in str(result)
    assert 'password' not in str(result)
    assert 'token=secret' not in str(result)
    dynamic = result['servers'][0]['routes'][1]
    assert dynamic['targets'][0]['dynamic'] is True
    assert result['warnings']


@pytest.mark.parametrize('text', [
    'http { server { listen 80; }',
    'http { include nginx.conf; }',
    'http { server { listen "80; } }',
    'http { server { listen 80 } }',
])
def test_reject_malformed_or_recursive(text):
    with pytest.raises(ParseError):
        parse_dump('nginx.conf', text)


def test_missing_include_and_stream_are_explicit():
    result = parse_dump('edge.conf', 'http { include /missing.conf; server { listen 80; } } stream { server { listen 9000; proxy_pass 10.0.0.1:9000; } }')
    assert any('include' in w for w in result['warnings'])
    assert any('stream' in w for w in result['warnings'])


def test_same_localhost_in_different_files_is_different_host():
    config = 'http { server { location / { proxy_pass http://127.0.0.1:9000; } } }'
    a = parse_dump('a.conf', config)['servers'][0]['routes'][1]['targets'][0]
    b = parse_dump('b.conf', config)['servers'][0]['routes'][1]['targets'][0]
    assert a['host'] != b['host']


def test_filename_validation_and_limits():
    for name in ('../edge.conf', 'edge.txt', 'edge/conf', '.conf'):
        with pytest.raises(ParseError):
            parse_dump(name, 'http {}')
    with pytest.raises(ParseError):
        parse_dump('edge.conf', 'http {' * 70 + '}' * 70)


def test_no_map_keys_auth_query_or_response_body_secrets():
    result = parse_dump('edge.conf', '''http {
map $http_authorization $ok { "Bearer TOPSECRET" 1; }
server { auth_request /auth?token=TOPSECRET;
location / { return 200 "TOPSECRET"; }
}}''')
    assert 'TOPSECRET' not in str(result)


def test_return_precedes_proxy_and_upstream_default_port_is_80():
    result = parse_dump('edge.conf', '''http {
upstream pool { server backend; }
server { location /deny { return 403; proxy_pass http://app; }
location / { proxy_pass https://pool; } }
}''')
    routes = result['servers'][0]['routes']
    assert routes[1]['action'] == 'return' and routes[1]['targets'] == []
    assert routes[2]['targets'][0]['port'] == 80


def test_include_glob_does_not_cross_directories():
    result = parse_dump('edge.conf', '''# configuration file /etc/nginx/nginx.conf:
http { include conf.d/*.conf; include conf.d/archive/*.conf; }
# configuration file /etc/nginx/conf.d/a.conf:
server { listen 80; }
# configuration file /etc/nginx/conf.d/archive/b.conf:
server { listen 81; }
''')
    assert len(result['servers']) == 2


def test_expanded_settings_budget():
    settings = '\n'.join(f'proxy_set_header Header{i} value;' for i in range(200))
    locations = '\n'.join(f'location /path{i} {{ proxy_pass http://app; }}' for i in range(200))
    with pytest.raises(ParseError, match='результат'):
        parse_dump('edge.conf', 'http { server { ' + settings + locations + '} }')


def test_server_return_precedes_location_and_redirect_credentials_hidden():
    doc = parse_dump('edge.conf', 'http { server { return 403; location / { return 200; proxy_pass http://app; } } }')
    assert doc['servers'][0]['routes'][1]['destination'] == '403'
    doc = parse_dump('edge.conf', 'http { server { return https://user:TOPSECRET@demo.example/; } }')
    assert 'TOPSECRET' not in str(doc)


def test_map_data_named_like_directives_is_hidden():
    doc = parse_dump('edge.conf', 'http { map $x $y { allow TOPSECRET; server TOPSECRET; } server { listen 80; } }')
    assert 'TOPSECRET' not in str(doc)


def test_long_token_rejected_and_root_alias_not_combined():
    with pytest.raises(ParseError, match='длинное'):
        parse_dump('edge.conf', 'http { server { root /' + 'x'*9000 + '; } }')
    doc = parse_dump('edge.conf', 'http { server { root /var/www; location /assets { alias /srv/assets; } } }')
    route = doc['servers'][0]['routes'][1]
    assert [s['name'] for s in route['settings'] if s['name'] in ('root', 'alias')] == ['alias']


def test_opaque_include_and_inline_key_and_error_uri():
    doc = parse_dump('edge.conf', '''# configuration file /etc/nginx/nginx.conf:
http { map $host $token { include tokens.conf; }
server { listen 443 ssl; ssl_certificate_key "data:TOPSECRET"; error_page 401 /auth?token=TOPSECRET; } }
# configuration file /etc/nginx/tokens.conf:
root TOPSECRET;
''')
    assert 'TOPSECRET' not in str(doc)


def test_unknown_handler_warning_and_exact_source_lines():
    doc = parse_dump('edge.conf', '# configuration file /etc/nginx/nginx.conf:\n\n\nhttp { server { location / { access_by_lua_block { return false; } proxy_pass http://app; } } }')
    assert doc['servers'][0]['line'] == 3
    assert doc['warnings']


def test_target_expansion_has_character_budget():
    members = '\n'.join('server ' + chr(97+i) + 'x'*4000 + ';' for i in range(20))
    locations = '\n'.join(f'location /p{i} {{ proxy_pass http://pool; }}' for i in range(100))
    with pytest.raises(ParseError, match='результат'):
        parse_dump('edge.conf', 'http { upstream pool {' + members + '} server {' + locations + '} }')


@pytest.mark.parametrize('target', ['$scheme://user:TOPSECRET@backend/path', '//user:TOPSECRET@backend/path'])
def test_variable_scheme_and_network_uri_credentials_hidden(target):
    doc = parse_dump('edge.conf', f'http {{ server {{ location / {{ proxy_pass {target}; }} location /go {{ return 302 {target}; }} }} }}')
    assert 'TOPSECRET' not in str(doc)
