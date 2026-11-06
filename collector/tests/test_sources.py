from datetime import datetime, timezone

import httpx
import pytest
from stools_threat_collector.adapters.kev import parse_kev
from stools_threat_collector.adapters.rss import parse_feed
from stools_threat_collector.fetcher import Fetcher, FetchError


def test_rss_chinese_identifiers_dates_and_html():
    xml = b'''<rss version="2.0"><channel><item><guid>a</guid><title>CVE-2026-12345</title>
    <link>https://example.org/a</link><pubDate>Thu, 05 Nov 2026 10:00:00 +0800</pubDate>
    <description>&lt;p&gt;CVE-2026-12345 and CVE-2026-23456&lt;/p&gt;</description></item></channel></rss>'''
    docs = parse_feed(xml, now=datetime(2026, 11, 5, 3, tzinfo=timezone.utc))
    assert docs[0]["published_at"] == "2026-11-05T02:00:00+00:00"
    assert docs[0]["identifiers"] == ["CVE-2026-12345", "CVE-2026-23456"]
    assert "<p>" not in docs[0]["text"]


def test_html_error_is_not_empty_feed():
    with pytest.raises(ValueError):
        parse_feed(b'<html><title>Access denied</title></html>')


def test_old_kev_retains_original_date():
    rows = parse_kev({"vulnerabilities": [{"cveID": "CVE-2020-12345", "dateAdded": "2021-11-03",
        "vulnerabilityName": "Old flaw", "shortDescription": "Observed attacks", "requiredAction": "Update"}]})
    assert rows[0]["published_at"].startswith("2021-11-03")
    assert rows[0]["exploitation_confirmed"]
    assert rows[0]["url"] == "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2020-12345"
    assert "https://nvd.nist.gov/vuln/detail/CVE-2020-12345" in rows[0]["links"]


def test_fetch_blocks_private_redirect_and_limits_decoded_body():
    def redirect(request):
        return httpx.Response(302, headers={"location": "http://127.0.0.1/admin"})
    fetcher = Fetcher(transport=httpx.MockTransport(redirect), resolver=lambda host: ["93.184.216.34"])
    with pytest.raises(FetchError):
        fetcher.get("https://example.org/rss")
    large = Fetcher(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b'x'*101)),
                    resolver=lambda host: ["93.184.216.34"], max_bytes=100)
    with pytest.raises(FetchError, match="size"):
        large.get("https://example.org/rss")


def test_conditional_headers_and_304():
    def unchanged(request):
        assert request.headers["if-none-match"] == '"v1"'
        return httpx.Response(304)
    fetcher = Fetcher(transport=httpx.MockTransport(unchanged), resolver=lambda host: ["93.184.216.34"])
    response = fetcher.get("https://example.org/rss", {"If-None-Match": '"v1"'})
    assert response.status_code == 304


def test_expired_source_budget_stops_before_dns():
    import time
    def resolve(host):
        pytest.fail('DNS called after total budget expired')
    fetcher = Fetcher(resolver=resolve)
    fetcher.deadline = time.monotonic() - 1
    with pytest.raises(FetchError, match='time budget'):
        fetcher.get('https://example.test/feed')


def test_blank_compose_proxy_uses_direct_transport():
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b'ok'))
    fetcher = Fetcher(proxy='', ca='', transport=transport, resolver=lambda _: ['93.184.216.34'])
    assert fetcher.get('https://example.test').content == b'ok'


def test_gzip_response_is_decoded_once():
    import gzip
    body = b'{"records":["one"]}'
    transport = httpx.MockTransport(lambda request: httpx.Response(200,
        headers={'Content-Encoding': 'gzip'}, content=gzip.compress(body)))
    fetcher = Fetcher(transport=transport, resolver=lambda _: ['93.184.216.34'])
    assert fetcher.get('https://example.test/feed').content == body
