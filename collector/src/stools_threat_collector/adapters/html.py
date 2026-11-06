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
    if body is None:
        raise ValueError("article layout not recognized")
    heading = soup.find("h1") or soup.find("title")
    title = heading.get_text(" ", strip=True)[:2000] if heading else url
    meta = soup.select_one('meta[property="article:published_time"], meta[itemprop="datePublished"], time[itemprop="datePublished"]')
    published = None
    if meta:
        try:
            date = datetime.fromisoformat(meta.get("content") or meta.get("datetime") or "")
            if date.tzinfo is not None:
                published = date.astimezone(timezone.utc).isoformat()
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
