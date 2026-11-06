"""Reviewed GitHub advisories; disclosure and updates are not exploitation evidence."""
import re
import time

import httpx

from ..fetcher import FetchError
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlsplit

IDENTIFIER = re.compile(r'(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})', re.I)


def checked_url(url):
    parts = urlsplit(url)
    if (parts.scheme != 'https' or parts.netloc != 'api.github.com'
            or parts.path != '/advisories' or parts.fragment):
        raise ValueError('GitHub advisory URL must be https://api.github.com/advisories')
    return url


def parse_advisory(item):
    ghsa = item.get('ghsa_id', '')
    if not re.fullmatch(r'GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}', ghsa, re.I):
        raise ValueError('invalid GitHub advisory ID')
    ids = [ghsa, item.get('cve_id') or '']
    ids.extend(entry.get('value', '') for entry in item.get('identifiers', []))
    identifiers = sorted({value for value in ids if IDENTIFIER.fullmatch(value)})
    description = item.get('description') or ''
    return {'external_id': ghsa, 'title': (item.get('summary') or ghsa)[:2000],
            'url': 'https://github.com/advisories/' + ghsa,
            'text': description[:262144], 'published_at': item.get('published_at'),
            'updated_at': item.get('updated_at'), 'identifiers': identifiers[:500],
            'links': [url[:2048] for url in (item.get('references') or [])
                      if isinstance(url, str) and url.startswith(('https://', 'http://'))][:100],
            'retracted': bool(item.get('withdrawn_at')), 'evidence_kind': 'advisory',
            'exploitation_confirmed': False, 'full_text': True,
            'truncated': len(description) > 262144}


def timestamp(value):
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def collect(source, checkpoint, fetcher, *, now=None, max_pages=5):
    base = checked_url(source['url'])
    now = now or datetime.now(timezone.utc)
    if checkpoint.get('next_url'):
        url = checked_url(checkpoint['next_url'])
        until = checkpoint['until']
    else:
        # Revisit a day of updates for delayed indexing. Original publication dates
        # are retained, so updates to old advisories do not make them fresh trends.
        since = (datetime.fromisoformat(checkpoint['since'].replace('Z', '+00:00')) - timedelta(days=1)
                 if checkpoint.get('since') else now - timedelta(days=30))
        until = timestamp(now)
        query = urlencode({'type': 'reviewed', 'sort': 'updated', 'direction': 'asc',
                           'per_page': 100, 'modified': timestamp(since) + '..' + until})
        url = base.split('?', 1)[0] + '?' + query
    documents, seen = [], set()
    for _ in range(max_pages):
        if url in seen:
            raise ValueError('repeated GitHub advisory pagination cursor')
        seen.add(url)
        try:
            response = fetcher.get(url, {'Accept': 'application/vnd.github+json',
                                        'X-GitHub-Api-Version': '2022-11-28'})
        except httpx.HTTPStatusError as exc:
            response = exc.response
            if response.status_code == 403 and response.headers.get('x-ratelimit-remaining') == '0':
                reset = response.headers.get('x-ratelimit-reset', '')
                delay = max(5, int(reset) - int(time.time()) + 5) if reset.isdigit() else 900
                raise FetchError('GitHub API rate limit exceeded; waiting for quota reset', delay) from exc
            raise FetchError(f'GitHub API HTTP {response.status_code}') from exc
        rows = response.json()
        if not isinstance(rows, list) or len(rows) > 100:
            raise ValueError('invalid GitHub advisory page')
        documents.extend(parse_advisory(item) for item in rows)
        next_url = response.links.get('next', {}).get('url')
        if not next_url:
            return documents, {'since': until}
        url = checked_url(next_url)
        if url in seen:
            raise ValueError('repeated GitHub advisory pagination cursor')
    return documents, {'next_url': url, 'until': until}
