from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit
import httpx
import pytest
from stools_threat_collector.collection import collect_batch
from stools_threat_collector.monitoring_contracts import CollectionWindow
from stools_threat_collector.fetcher import Fetcher

NOW = datetime(2026, 11, 7, tzinfo=timezone.utc)

def fake(handler):
    return Fetcher(transport=httpx.MockTransport(handler), resolver=lambda _: ['93.184.216.34'])

def test_nvd_pagination_resumes_without_gaps():
    seen = []
    def handler(request):
        q = parse_qs(request.url.query.decode())
        index = int(q['startIndex'][0]); seen.append(index)
        return httpx.Response(200, json={'startIndex': index, 'resultsPerPage': 1, 'totalResults': 3,
            'vulnerabilities': [{'cve': {'id': f'CVE-2011-{3400+index}', 'published': '2011-11-01T12:00:00.000',
                'lastModified': '2026-11-06T12:00:00.000', 'descriptions': [{'lang':'en','value':'old flaw'}]}}]})
    source = {'id':'stable','url':'https://services.nvd.nist.gov/rest/json/cves/2.0','adapter':'nvd'}
    cp = {}; ids = []
    for _ in range(3):
        batch = collect_batch(source, cp, fake(handler), now=NOW)
        cp = batch.checkpoint; ids += [d['external_id'] for d in batch.documents]
    assert seen == [0, 1, 2] and len(set(ids)) == 3
    assert not batch.continuation
    assert cp['last_complete'] == NOW.isoformat()
    assert batch.documents[0]['published_at'].startswith('2011-')
    assert batch.documents[0]['updated_at'].startswith('2026-')

def test_fallback_preserves_source_identity():
    def handler(request):
        if request.headers['host'] == 'primary.test':
            return httpx.Response(200, text='<html>blocked</html>')
        return httpx.Response(200, text='<rss version="2.0"><channel><item><guid>one</guid><link>https://mirror.test/a</link><title>CVE-2026-12345</title></item></channel></rss>')
    source = {'id':'stable','url':'https://primary.test/feed','fallback_urls':['https://mirror.test/feed'],'adapter':'rss'}
    batch = collect_batch(source, {}, fake(handler), now=NOW)
    assert batch.documents[0]['external_id'] == 'one'
    assert batch.coverage['source_id'] == 'stable'
    assert batch.coverage['fetch_url'] == 'https://mirror.test/feed'

def test_304_keeps_checkpoint():
    cp = {'parser_version':2,'etag':'v1'}
    batch = collect_batch({'id':'s','url':'https://example.test/feed','adapter':'rss'}, cp,
        fake(lambda _: httpx.Response(304)), now=NOW)
    assert batch.documents == [] and batch.checkpoint == cp

def test_invalid_feed_and_internal_fallback_are_errors():
    source = {'id':'s','url':'https://example.test/feed','adapter':'rss'}
    with pytest.raises(ValueError):
        collect_batch(source, {}, fake(lambda _: httpx.Response(200, text='<html>blocked</html>')))
    fetcher = Fetcher(transport=httpx.MockTransport(lambda _: httpx.Response(302, headers={'location':'http://127.0.0.1'})),
        resolver=lambda host: ['127.0.0.1'] if host == '127.0.0.1' else ['93.184.216.34'])
    with pytest.raises(ValueError):
        collect_batch({**source,'fallback_urls':['http://127.0.0.1']}, {}, fetcher)

def test_window_requires_ordered_aware_dates():
    with pytest.raises(ValueError):
        CollectionWindow(date_from='2026-11-07T00:00:00Z', date_to='2026-11-01T00:00:00Z')
    with pytest.raises(ValueError):
        CollectionWindow(date_from='2026-11-07T00:00:00')

def test_redirect_does_not_forward_secret_headers():
    def handler(request):
        if request.headers['host'] == 'a.test':
            return httpx.Response(302, headers={'location':'https://b.test/feed'})
        assert 'authorization' not in request.headers and 'apikey' not in request.headers
        return httpx.Response(200)
    fake(handler).get('https://a.test/feed', {'Authorization':'secret','apiKey':'secret'}, {'a.test','b.test'})

def test_msrc_monthly_payload_uses_bounded_adapter_allowance():
    import json
    def handler(request):
        if request.url.path.endswith('/updates'):
            return httpx.Response(200, json={'value': [{'ID': 'current', 'CurrentReleaseDate': datetime.now(timezone.utc).isoformat()}]})
        payload = {'Vulnerability': [{'CVE': 'CVE-2026-12345', 'Title': {'Value': 'Security update'}}],
                   'ProductTree': {'padding': ' ' * (5 * 1024 * 1024)}}
        return httpx.Response(200, content=json.dumps(payload).encode())
    fetcher = fake(handler)
    batch = collect_batch({'id': 'msrc', 'adapter': 'msrc', 'url': 'https://api.msrc.microsoft.com/updates'}, {}, fetcher)
    assert [d['external_id'] for d in batch.documents] == ['CVE-2026-12345']
    assert fetcher.max_bytes == 32 * 1024 * 1024
