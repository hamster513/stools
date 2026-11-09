import calendar
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin

import feedparser
from bs4 import BeautifulSoup

CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
GHSA = re.compile(r"\bGHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}\b", re.IGNORECASE)
BDU = re.compile(r"\bBDU[:\-]\d{4}[-:]\d{3,}\b", re.IGNORECASE)
PARSER_VERSION = 2


def identifiers(*values):
    text = " ".join(values)
    return sorted({match.upper() for pattern in (CVE, GHSA, BDU) for match in pattern.findall(text)})[:500]


def recent_publication(published, now):
    if not published:
        return True
    date = datetime.fromisoformat(published)
    return now - timedelta(days=30) <= date <= now + timedelta(minutes=5)


def plain_html(html):
    soup = BeautifulSoup(html, "html.parser")
    for node in soup(["script", "style", "nav", "footer", "header", "form"]):
        node.decompose()
    return soup.get_text(" ", strip=True)


def entry_date(entry, key):
    # Bypass feedparser's compatibility aliases between updated and published.
    value = dict.get(entry, key + "_parsed")
    try:
        return datetime.fromtimestamp(calendar.timegm(value), timezone.utc).isoformat() if value else None
    except (ValueError, OverflowError, OSError):
        return None


def parse_feed(data, now=None):
    feed = feedparser.parse(data)
    if not feed.get("version"):
        title = BeautifulSoup(data[:20000], 'html.parser').title
        if title and any(word in title.get_text().lower() for word in ('are we human', 'just a moment', 'access denied')):
            raise ValueError('publisher requires browser verification')
        raise ValueError("response is not RSS or Atom")
    if feed.get("bozo") and not feed.entries:
        raise ValueError("malformed feed")
    now = now or datetime.now(timezone.utc)
    documents = []
    for entry in feed.entries[:500]:
        published = entry_date(entry, "published")
        if not recent_publication(published, now):
            continue
        url = entry.get("link", "")
        identity = entry.get("id") or url
        if not identity or not url:
            continue
        content = entry.get("content") or []
        html = content[0].get("value", "") if content else entry.get("summary", "")
        text = plain_html(html)
        title = plain_html(entry.get("title", ""))[:2000]
        soup = BeautifulSoup(html, "html.parser")
        links = sorted({urljoin(url, link.get("href")) for link in soup.find_all("a", href=True)})[:100]
        documents.append({"external_id": str(identity)[:1024], "title": title, "url": url[:2048],
                          "text": text[:262144], "published_at": published,
                          "updated_at": entry_date(entry, "updated"), "links": links,
                          "identifiers": identifiers(title, text, *links),
                          "full_text": bool(content), "truncated": len(text) > 262144})
    return documents


def collect(source, checkpoint, fetcher, now=None):
    now = now or datetime.now(timezone.utc)
    headers = {}
    # Replay the current feed once after parser fixes; subsequent runs use HTTP caching.
    if checkpoint.get("parser_version") == PARSER_VERSION:
        if checkpoint.get("etag"):
            headers["If-None-Match"] = checkpoint["etag"]
        if checkpoint.get("modified"):
            headers["If-Modified-Since"] = checkpoint["modified"]
    # These official feeds include full articles and exceed the default 5 MiB.
    large_feeds = {'https://www.cisa.gov/cybersecurity-advisories/all.xml',
                   'https://www.elastic.co/security-labs/rss/feed.xml'}
    old_limit = fetcher.max_bytes
    try:
        if source['url'] in large_feeds:
            fetcher.max_bytes = 16 * 1024 * 1024
        response = fetcher.get(source["url"], headers)
    finally:
        fetcher.max_bytes = old_limit
    if response.status_code == 304:
        return [], checkpoint
    documents = parse_feed(response.content, now=now)
    from urllib.parse import urlsplit

    import httpx

    from ..fetcher import FetchError
    from .html import article
    for document in documents:
        import time
        if time.monotonic() >= fetcher.deadline:
            break
        # Only fetch articles on the configured publisher domain. A short RSS
        # extract remains useful when full text is unavailable or paywalled.
        if document["full_text"] and document["published_at"]:
            continue
        if urlsplit(document["url"]).hostname != urlsplit(source["url"]).hostname:
            continue
        try:
            full = article(fetcher, document["url"])
            document["identifiers"] = sorted(set(document["identifiers"]) | set(full["identifiers"]))[:500]
            document["links"] = sorted(set(document["links"]) | set(full["links"]))[:100]
            if len(full["text"]) > len(document["text"]):
                document.update({key: full[key] for key in ("text", "full_text", "truncated")})
            if not document["published_at"]:
                document["published_at"] = full["published_at"]
        except (FetchError, httpx.HTTPError, ValueError):
            continue
    documents = [document for document in documents if recent_publication(document["published_at"], now)]
    return documents, {"parser_version": PARSER_VERSION, "etag": response.headers.get("etag"),
                       "modified": response.headers.get("last-modified")}
