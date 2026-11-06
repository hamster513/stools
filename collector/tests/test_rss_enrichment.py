from datetime import datetime, timezone
from html import escape

import httpx
import pytest

from stools_threat_collector.adapters import html, rss
from stools_threat_collector.fetcher import Fetcher


NOW = datetime(2026, 11, 6, 15, tzinfo=timezone.utc)


def feed(description="Feed evidence", title="cve-2026-12345", published="2026-11-06T12:00:00Z"):
    date = f"<pubDate>{published}</pubDate>" if published else ""
    return (f'<rss version="2.0"><channel><item><guid>item-1</guid><title>{title}</title>'
            f'<link>https://example.org/story</link>{date}'
            f'<description>{escape(description)}</description></item></channel></rss>').encode()


def fetcher(feed_body, article_body):
    def respond(request):
        body = feed_body if request.url.path == "/feed" else article_body
        return httpx.Response(200, content=body)
    return Fetcher(transport=httpx.MockTransport(respond), resolver=lambda _: ["93.184.216.34"])


def collect(feed_body, article_body):
    documents, _ = rss.collect({"url": "https://example.org/feed"}, {}, fetcher(feed_body, article_body), now=NOW)
    return documents


def test_feed_canonicalizes_valid_cve_and_ghsa_from_title_body_and_links():
    content = ('<p>cve-2026-23456 ghsa-jfh8-c2jp-5v3q CVE-2026-123 xCVE-2026-99999 '
               'GHSA-aaaa-bbbb-cccc</p><a href="https://github.com/advisories/GHSA-2345-6789-cfgh">advisory</a>')
    document = rss.parse_feed(feed(content), now=NOW)[0]
    assert document["identifiers"] == ["CVE-2026-12345", "CVE-2026-23456", "GHSA-2345-6789-CFGH", "GHSA-JFH8-C2JP-5V3Q"]


def test_enrichment_preserves_feed_identity_dates_and_unions_evidence(monkeypatch):
    content = '<p>Feed cve-2026-23456</p><a href="/feed-reference">source</a>'
    page = b"""<h1>Different article heading</h1><meta property="article:published_time" content="2026-11-05T01:00:00Z">
    <article><div class="articleBody"><p>A detailed report describes attacks using cve-2026-34567
    and ghsa-jfh8-c2jp-5v3q against vulnerable systems.</p><a href="/article-reference">advisory</a></div>
    <aside><a href="/unrelated">CVE-2026-99999</a></aside></article>"""
    doc = collect(feed(content), page)[0]
    assert doc["external_id"] == "item-1"
    assert doc["url"] == "https://example.org/story"
    assert doc["title"] == "cve-2026-12345"
    assert doc["published_at"] == "2026-11-06T12:00:00+00:00"
    assert doc["identifiers"] == ["CVE-2026-12345", "CVE-2026-23456", "CVE-2026-34567", "GHSA-JFH8-C2JP-5V3Q"]
    assert doc["links"] == ["https://example.org/article-reference", "https://example.org/feed-reference"]
    assert doc["full_text"] is True
    assert "detailed report" in doc["text"]
    assert "99999" not in doc["text"]


@pytest.mark.parametrize("body", [
    '<div id="content"><nav>Home</nav><aside>Related CVE-2026-99999</aside></div>',
    '<article><p>Subscribe</p></article>',
    '<article><aside>CVE-2026-99999 related story</aside></article>',
])
def test_bad_article_does_not_erase_feed_evidence(body):
    summary = '<p>Useful feed report about active exploitation of cve-2026-23456.</p><a href="/reference">Source</a>'
    doc = collect(feed(summary), body.encode())[0]
    assert "Useful feed report" in doc["text"]
    assert doc["identifiers"] == ["CVE-2026-12345", "CVE-2026-23456"]
    assert doc["links"] == ["https://example.org/reference"]
    assert doc["full_text"] is False


def test_article_prefers_specific_body_and_removes_related_widgets():
    page = b"""<article><h1>cve-2026-12345 report</h1><div class="article-content">
    <p>This detailed report covers ghsa-jfh8-c2jp-5v3q and contains supporting evidence of exploitation.</p>
    <div class="related-posts"><a href="/other">CVE-2026-99999</a></div></div>
    <aside>Related CVE-2026-88888</aside></article>"""
    doc = html.article(fetcher(b"", page), "https://example.org/story")
    assert doc["identifiers"] == ["CVE-2026-12345", "GHSA-JFH8-C2JP-5V3Q"]
    assert doc["links"] == []
    assert "99999" not in doc["text"]


def test_article_supports_securitylab_body_and_verified_publication_time():
    page = b"""<h1>Security report</h1><meta property="article:published_time" content="2026-11-06T15:00:00+03:00">
    <div itemprop="articleBody"><p>A detailed report covering CVE-2026-12345 describes the vulnerable product and fixes.</p></div>"""
    doc = html.article(fetcher(b"", page), "https://example.org/story")
    assert doc["published_at"] == "2026-11-06T12:00:00+00:00"
    assert doc["identifiers"] == ["CVE-2026-12345"]


@pytest.mark.parametrize("published, expected", [
    (None, None), ("not a date", None),
    ("2026-11-06T15:04:00Z", "2026-11-06T15:04:00+00:00"),
])
def test_feed_missing_invalid_and_clock_skew_dates_are_not_fabricated(published, expected):
    assert rss.parse_feed(feed(published=published), now=NOW)[0]["published_at"] == expected


@pytest.mark.parametrize("published", ["2020-01-01T00:00:00Z", "2026-11-06T15:06:00Z", "2099-01-01T00:00:00Z"])
def test_feed_drops_old_and_future_publication_dates(published):
    assert rss.parse_feed(feed(published=published), now=NOW) == []


def test_atom_updated_is_never_used_as_publication_date():
    xml = b"""<feed xmlns="http://www.w3.org/2005/Atom"><entry><id>a</id><title>cve-2026-12345</title>
    <link href="https://example.org/a"/><updated>2026-11-06T12:00:00Z</updated><summary>Evidence</summary></entry></feed>"""
    doc = rss.parse_feed(xml, now=NOW)[0]
    assert doc["published_at"] is None
    assert doc["updated_at"] == "2026-11-06T12:00:00+00:00"


@pytest.mark.parametrize("meta, expected", [
    ('property="article:published_time" content="2026-11-06T15:00:00+03:00"', "2026-11-06T12:00:00+00:00"),
    ('itemprop="datePublished" content="2026-11-06T12:00:00Z"', "2026-11-06T12:00:00+00:00"),
    ('property="article:modified_time" content="2026-11-06T12:00:00Z"', None),
    ('property="article:published_time" content="invalid"', None),
    ('property="article:published_time" content="2026-11-06T12:00:00"', None),
])
def test_undated_feed_uses_only_verified_article_publication(meta, expected):
    page = f'<meta {meta}><article><p>A detailed report about exploitation provides evidence, affected versions and patch guidance.</p></article>'
    doc = collect(feed(published=None), page.encode())[0]
    assert doc["published_at"] == expected


@pytest.mark.parametrize("published", ["2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z"])
def test_undated_feed_with_old_or_future_article_date_is_not_recent(published):
    page = f'<meta property="article:published_time" content="{published}"><article><p>A detailed report about exploitation provides evidence, affected versions and patch guidance.</p></article>'
    assert collect(feed(published=None), page.encode()) == []


@pytest.mark.parametrize("checkpoint", [{"etag": '"old"', "modified": "yesterday"}, {"parser_version": 1, "etag": '"old"'}])
def test_old_parser_checkpoint_refetches_feed_once(checkpoint):
    def respond(request):
        assert "if-none-match" not in request.headers
        assert "if-modified-since" not in request.headers
        return httpx.Response(200, content=feed(), headers={"etag": '"new"', "last-modified": "today"})
    client = Fetcher(transport=httpx.MockTransport(respond), resolver=lambda _: ["93.184.216.34"])
    _, updated = rss.collect({"url": "https://example.org/feed"}, checkpoint, client)
    assert updated == {"parser_version": 2, "etag": '"new"', "modified": "today"}


def test_current_parser_checkpoint_keeps_conditional_fetch():
    checkpoint = {"parser_version": 2, "etag": '"current"', "modified": "today"}
    def respond(request):
        assert request.headers["if-none-match"] == '"current"'
        assert request.headers["if-modified-since"] == "today"
        return httpx.Response(304)
    client = Fetcher(transport=httpx.MockTransport(respond), resolver=lambda _: ["93.184.216.34"])
    documents, updated = rss.collect({"url": "https://example.org/feed"}, checkpoint, client)
    assert documents == []
    assert updated == checkpoint


def test_undated_full_content_feed_can_recover_article_publication_date():
    xml = b"""<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel><item>
    <guid>item-1</guid><title>cve-2026-12345</title><link>https://example.org/story</link>
    <content:encoded><![CDATA[<p>The complete feed report contains the original detailed evidence and remediation instructions.
    It must remain available even when the article body is shorter than the full feed content.</p>]]></content:encoded>
    </item></channel></rss>"""
    page = b"""<meta property="article:published_time" content="2026-11-06T12:00:00Z">
    <article><p>A detailed article reports the same vulnerability and contains verified publication metadata.</p></article>"""
    doc = collect(xml, page)[0]
    assert doc["published_at"] == "2026-11-06T12:00:00+00:00"
    assert "complete feed report" in doc["text"]
    assert doc["full_text"] is True
