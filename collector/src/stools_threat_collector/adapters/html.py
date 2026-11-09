import re
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from .rss import identifiers, plain_html


def article(fetcher, url):
    response = fetcher.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    body = None
    # Specific publisher bodies precede broad article wrappers containing related news.
    for selector in ('[itemprop="articleBody"]', '.articleBody', '.article-content', '.article-body',
                     '.entry-content', '.post-content', '.zox-post-body', '#article-body', 'article'):
        body = soup.select_one(selector)
        if body is not None:
            break
    if body is None and urlsplit(url).hostname == 'securitymedia.ru':
        body = soup.select_one('main .tekst')
    if body is None:
        raise ValueError("article layout not recognized")
    heading = soup.find("h1") or soup.find("title")
    title = heading.get_text(" ", strip=True)[:2000] if heading else url
    meta = soup.select_one('meta[property="article:published_time"], meta[itemprop="datePublished"]')
    if meta is None:
        meta = body.select_one('time[itemprop="datePublished"], time[datetime]')
    if meta is None and urlsplit(url).hostname == 'hackware.ru':
        meta = soup.select_one('main .article-meta-box time[datetime]')
    published = None
    if meta:
        try:
            date = datetime.fromisoformat(meta.get("content") or meta.get("datetime") or "")
            # A date-only publisher value has day precision, never collection time.
            if date.tzinfo is None and len(meta.get('datetime', '')) == 10:
                date = date.replace(tzinfo=timezone.utc)
            if date.tzinfo is not None:
                published = date.astimezone(timezone.utc).isoformat()
        except ValueError:
            pass
    if published is None and urlsplit(url).hostname == 'securitymedia.ru':
        heading_date = body.find('h1')
        label = heading_date.find_next_sibling('p') if heading_date else None
        match = re.fullmatch(r'(\d{1,2}) ([а-я]+) (\d{4})', label.get_text(strip=True)) if label else None
        months = 'января февраля марта апреля мая июня июля августа сентября октября ноября декабря'.split()
        if match and match[2] in months:
            try:
                published = datetime(int(match[3]), months.index(match[2])+1, int(match[1]), tzinfo=timezone.utc).isoformat()
            except ValueError:
                pass
    for node in body.select('script, style, nav, footer, header, form, aside, [role="complementary"], '
                            '[class*="related"], [id*="related"], #comments, .comments, .comment-list, '
                            '.newsletter, .zox-post-body-bot'):
        node.decompose()
    text = plain_html(str(body))
    if len(text) < 80:
        raise ValueError("article body too short")
    links = sorted({urljoin(url, a["href"]) for a in body.find_all("a", href=True)})[:100]
    return {"external_id": url, "url": url, "title": title,
            "text": text[:262144], "published_at": published, "full_text": True,
            "truncated": len(text) > 262144, "identifiers": identifiers(title, text, *links),
            "links": links}


def collect(source, checkpoint, fetcher):
    page = fetcher.get(source["url"])
    soup = BeautifulSoup(page.content, "html.parser")
    links = []
    for a in soup.find_all("a", href=True):
        if not re.search(r"漏洞|风险提示|安全公告", a.get_text()):
            continue
        url = urljoin(source["url"], a["href"])
        if urlsplit(url).hostname == urlsplit(source["url"]).hostname and url not in links:
            links.append(url)
    if not links:
        raise ValueError("CNCERT advisory listing not recognized")
    return [article(fetcher, url) for url in links[:20]], {}


def collect_listing(source, checkpoint, fetcher):
    """Explicit publisher layouts; do not crawl navigation or unrelated domains."""
    import time
    import httpx
    from ..monitoring_contracts import CollectionBatch
    host=urlsplit(source['url']).hostname
    patterns={
        'hackware.ru': r'^/\?p=\d+$',
        'www.yeswehack.com': r'^/(?:dojo|learn-bug-bounty|vulnerability|community|customer-stories|news)/[^/?#]+$',
        'securitymedia.ru': r'^/news/[^/?#]+/?$',
    }
    if host not in patterns:
        raise ValueError('HTML article listing not recognized')
    response=fetcher.get(source['url'])
    soup=BeautifulSoup(response.content,'html.parser')
    links=[]
    for a in soup.select('main a[href], article a[href], a[href]'):
        url=urljoin(source['url'],a['href']);parts=urlsplit(url)
        path=parts.path+('?' + parts.query if parts.query else '')
        if parts.hostname==host and re.fullmatch(patterns[host],path) and url not in links:
            links.append(url)
    if not links:
        raise ValueError('HTML article listing not recognized')
    docs=[];failures=0;first_error=None
    for url in links[:20]:
        if time.monotonic()>=fetcher.deadline:
            break
        try:
            docs.append(article(fetcher,url))
        except (ValueError,httpx.HTTPError) as exc:
            failures+=1
            if first_error is None:
                first_error=exc
    if not docs:
        if first_error is not None:
            raise first_error
        from ..fetcher import FetchError
        raise FetchError('source time budget exceeded')
    incomplete=failures>0 or len(docs)<min(len(links),20)
    return CollectionBatch(documents=docs,checkpoint={},coverage={'partial':incomplete},
                           counters={'fetched':len(docs),'failed_articles':failures})
