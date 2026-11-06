# ruff: noqa: SIM117
import httpx
import pytest

from api.modules.vm.services.trends.client import CollectorClient, CollectorError
from api.modules.vm.services.trends.settings import TrendConnectionIn


def test_url_and_proxy_validation():
    for url in ('http://collector.test', 'https://user:pass@collector.test', 'https://collector.test/#bad'):
        with pytest.raises(ValueError):
            TrendConnectionIn(url=url)
    with pytest.raises(ValueError):
        TrendConnectionIn(url='https://collector.test', proxy_enabled=True)
    value = TrendConnectionIn(url='https://collector.test:8443', token='secret', proxy_enabled=True,
                              proxy_host='proxy.test', proxy_port=3128)
    assert value.proxy_port == 3128


def test_client_has_explicit_route_no_environment_and_no_redirect(monkeypatch):
    captured = {}
    real = httpx.Client
    def client(**kwargs):
        captured.update(kwargs)
        kwargs['transport'] = httpx.MockTransport(lambda r: httpx.Response(200, json={
            'protocol_version': 1, 'collector_id': 'one', 'epoch': 'one', 'last_seq': 0}))
        return real(**kwargs)
    monkeypatch.setattr(httpx, 'Client', client)
    conn = TrendConnectionIn(url='https://collector.test', token='secret')
    with CollectorClient(conn) as remote:
        assert remote.info()['protocol_version'] == 1
    assert captured['trust_env'] is False
    assert captured['follow_redirects'] is False


def test_status_is_reported_without_secret(monkeypatch):
    real = httpx.Client
    monkeypatch.setattr(httpx, 'Client', lambda **kw: real(**kw, transport=httpx.MockTransport(
        lambda r: httpx.Response(407, text='secret password should not escape'))))
    with CollectorClient(TrendConnectionIn(url='https://collector.test', token='topsecret')) as remote:
        with pytest.raises(CollectorError, match='407') as error:
            remote.info()
    assert 'topsecret' not in str(error.value)
    assert 'password' not in str(error.value)
