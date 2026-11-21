
import httpx
import pytest
from pydantic import ValidationError

from api.modules.radar.nettrace_client import (
    NettraceClient,
    NettraceError,
    PathRequest,
    validate_url,
)

SET = 'set-0123456789abcdef'


def test_url_and_path_validation():
    assert validate_url('https://nettrace.example/') == 'https://nettrace.example'
    for url in ('http://local', 'https://u:p@host', 'https://host/path', 'https://host?key=x', 'https://host/#x'):
        with pytest.raises(ValueError):
            validate_url(url)
    base = {'source': {'address': '198.51.100.1'}, 'destination': {'address': '203.0.113.1', 'port': 443}, 'protocol': 'tcp'}
    assert PathRequest.model_validate(base).protocol == 'tcp'
    for source in ({'address': '10.0.0.0/8'}, {'address': '::1'}, {'address': '224.0.0.1'},
                   {'address': '198.51.100.1', 'port': 50000}, {'address': '198.51.100.1', 'entry_interface': 'outside'}):
        with pytest.raises(ValidationError):
            PathRequest.model_validate({**base, 'source': source})


def make(handler, **kwargs):
    return NettraceClient('https://nettrace.example', 'ntk_test_SECRET', transport=httpx.MockTransport(handler), **kwargs)


def test_pagination_and_key_only_in_header():
    calls = []
    def handler(req):
        calls.append(req)
        assert req.headers['Authorization'] == 'Bearer ntk_test_SECRET'
        assert 'SECRET' not in str(req.url)
        offset = int(req.url.params.get('offset', 0))
        return httpx.Response(200, json={'total': 2, 'items': [{'id': str(offset)}], 'snapshot': {'id': 'same'}})
    with make(handler) as client:
        result, meta = client.pages('/devices', page_size=1)
    assert len(result) == 2 and meta['total'] == 2 and len(calls) == 2


def test_page_snapshot_change_and_missing_page_rejected():
    for changed in (False, True):
        def handler(req, changed=changed):
            offset = int(req.url.params.get('offset', 0))
            return httpx.Response(200, json={'total': 2, 'items': [{'id': str(offset)}] if changed or offset == 0 else [],
                                           'snapshot': {'id': str(offset) if changed else 'same'}})
        with make(handler) as client, pytest.raises(NettraceError):
            client.pages('/devices/x/interfaces', page_size=1)


def test_no_redirects_secret_echo_and_retry_after():
    calls, sleeps = [], []
    def handler(req):
        calls.append(req)
        return httpx.Response(429, headers={'Retry-After': '2'}) if len(calls) == 1 else httpx.Response(200, json={'message': 'ntk_test_SECRET'})
    with make(handler, wait=sleeps.append) as client:
        assert client.request('GET', '/snapshot-set')['message'] == '[скрыто]'
    assert sleeps == [2]
    for code in (302, 401, 403, 500):
        with make(lambda req, code=code: httpx.Response(code, headers={'Location': 'https://other.example'}, text='ntk_test_SECRET')) as client:
            with pytest.raises(NettraceError) as error:
                client.request('GET', '/snapshot-set')
            assert 'SECRET' not in str(error.value)


def test_response_bounds_and_bad_json():
    for raw in (b'not json', b'['+b'1,'*20+b'1]'):
        with make(lambda req, raw=raw: httpx.Response(200, content=raw), response_limit=16) as client, pytest.raises(NettraceError):
            client.request('GET', '/devices')


def test_escaped_token_echo_is_redacted_after_json_decoding():
    raw = b'{"nested": [{"\\u006etk_test_SECRET": "prefix \\u006etk_test_SECRET suffix"}]}'
    with NettraceClient('https://nt.example', 'ntk_test_SECRET', transport=httpx.MockTransport(lambda req: httpx.Response(200, content=raw))) as client:
        data = client.request('GET', '/devices')
    assert data == {'nested': [{'[скрыто]': 'prefix [скрыто] suffix'}]}
