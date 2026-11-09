from datetime import datetime, timezone
import httpx
import pytest
from stools_threat_collector.collection import collect_batch
from stools_threat_collector.fetcher import Fetcher
from stools_threat_collector.monitoring_contracts import CollectionWindow

NOW = datetime(2026, 11, 7, tzinfo=timezone.utc)
def fetch(handler):
    return Fetcher(transport=httpx.MockTransport(handler), resolver=lambda _: ['93.184.216.34'])

def test_large_publisher_feed_allowance_is_scoped_and_restored():
    body = b'<rss version="2.0"><channel><description>' + b' ' * (6*1024*1024) + b'</description></channel></rss>'
    f = fetch(lambda r: httpx.Response(200,content=body))
    assert not collect_batch({'adapter':'rss','url':'https://www.cisa.gov/cybersecurity-advisories/all.xml'}, {}, f, now=NOW).documents
    assert f.max_bytes == 5*1024*1024
    with pytest.raises(ValueError,match='size'):
        collect_batch({'adapter':'rss','url':'https://unrelated.test/rss'}, {}, f, now=NOW)

def test_html_listing_keeps_only_publisher_articles_and_original_date():
    def handler(r):
        if r.url.path=='/blog': return httpx.Response(200,text='<main><a href="/dojo/example">Story</a><a href="https://other.test/dojo/evil">Other</a><a href="/blog/lab">Category</a></main>')
        return httpx.Response(200,text='<meta property="article:published_time" content="2026-11-05T10:00:00Z"><h1>CVE-2026-12345 explained</h1><article>'+('Exploit details and patch. '*8)+'</article>')
    b=collect_batch({'adapter':'html','url':'https://www.yeswehack.com/blog'}, {}, fetch(handler), now=NOW)
    assert len(b.documents)==1
    assert b.documents[0]['url']=='https://www.yeswehack.com/dojo/example'
    assert b.documents[0]['identifiers']==['CVE-2026-12345']
    assert b.documents[0]['published_at']=='2026-11-05T10:00:00+00:00'

def test_html_challenge_is_failure_not_success_with_zero_documents():
    with pytest.raises(ValueError,match='listing'):
        collect_batch({'adapter':'html','url':'https://hackware.ru/'},{},fetch(lambda r:httpx.Response(200,text='<title>Are we human?</title>')),now=NOW)

def test_nvidia_index_uses_initial_date_and_exact_bulletin_url():
    from stools_threat_collector.adapters.nvidia import parse_index
    rows=parse_index('| [5910](5910/5910.md) | CUDA Toolkit | 2026-11-03 | 2026-11-06 | [CVE-2026-65160](5910/CVE-2026-65160.json) |',2026)
    assert rows[0]['url']=='https://github.com/NVIDIA/product-security/blob/main/2026/5910/5910.md'
    assert rows[0]['published_at']=='2026-11-03T00:00:00+00:00'
    assert rows[0]['updated_at']=='2026-11-06T00:00:00+00:00'
    assert rows[0]['identifiers']==['CVE-2026-65160']

def test_fetch_error_explains_block_without_query_or_secrets():
    from stools_threat_collector.monitoring import source_error
    request=httpx.Request('GET','https://example.test/feed?token=secret')
    exc=httpx.HTTPStatusError('secret',request=request,response=httpx.Response(403,request=request))
    assert source_error(exc)=='HTTP 403: доступ запрещён издателем'
    assert 'secret' not in source_error(httpx.ConnectError('proxy password secret'))

def test_bdu_certificate_bundle_loads_without_changing_other_source_trust():
    from stools_threat_collector.outbound_profiles import make_fetcher
    ordinary=make_fetcher({'url':'https://example.org/feed'})
    bdu=make_fetcher({'url':'https://bdu.fstec.ru/ubi/vul/rss'})
    assert bdu.context.check_hostname and ordinary.context.check_hostname
    assert bdu.context.cert_store_stats()['x509_ca'] > ordinary.context.cert_store_stats()['x509_ca']

def test_article_day_date_is_preserved_not_replaced_by_collection_time():
    from stools_threat_collector.adapters.html import article
    f=fetch(lambda r:httpx.Response(200,text='<h1>News</h1><article><time datetime="2026-10-08">08.10.2026</time>'+('Details. '*20)+'</article>'))
    assert article(f,'https://hackware.ru/?p=22609')['published_at']=='2026-10-08T00:00:00+00:00'

def test_article_date_ignores_global_header_clock():
    from stools_threat_collector.adapters.html import article
    page='<header><time datetime="2026-11-07">Today</time></header><main><h1>News</h1><article><time datetime="2026-10-08">Published</time>'+('Details. '*20)+'</article></main>'
    assert article(fetch(lambda r:httpx.Response(200,text=page)),'https://hackware.ru/?p=1')['published_at']=='2026-10-08T00:00:00+00:00'

def test_html_access_denied_is_not_reported_as_layout_error():
    def handler(r):
        if r.url.path=='/blog':return httpx.Response(200,text='<main><a href="/dojo/example">Story</a></main>')
        return httpx.Response(403)
    with pytest.raises(httpx.HTTPStatusError):
        collect_batch({'adapter':'html','url':'https://www.yeswehack.com/blog'},{},fetch(handler),now=NOW)

def test_securitymedia_preserves_historical_article_date():
    from stools_threat_collector.adapters.html import article
    html='<main class="stvol"><div class="tekst"><h1>Транспортная безопасность</h1><p>18 ноября 2021</p><p>'+('Описание требований. '*12)+'</p></div></main>'
    doc=article(fetch(lambda r:httpx.Response(200,text=html)),'https://securitymedia.ru/news/requirements')
    assert doc['published_at']=='2021-11-18T00:00:00+00:00'
    assert not doc['identifiers']
