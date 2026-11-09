"""Uniform batches around existing adapters; never reset a durable cursor to retry."""
from datetime import datetime, timezone
from urllib.parse import urlsplit
import httpx
from .adapters import github, html, kev, msrc, nvd, nvidia, rss, telegram, telegram_web
from .fetcher import FetchError
from .monitoring_contracts import CollectionBatch, CollectionWindow

ADAPTERS = {'rss':rss.collect,'kev':kev.collect,'msrc':msrc.collect,'cncert':html.collect,
            'telegram':telegram.collect,'github':github.collect,'nvd':nvd.collect,'html':html.collect_listing,'nvidia':nvidia.collect}


class SourceFetcher:
    def __init__(self, fetcher, source):
        self.fetcher = fetcher
        self.source = source
        self.deadline = fetcher.deadline
    @property
    def max_bytes(self):
        return self.fetcher.max_bytes

    @max_bytes.setter
    def max_bytes(self, value):
        self.fetcher.max_bytes = value

    def get(self, url, headers=None, allowed_hosts=None):
        headers = dict(headers or {})
        if self.source.get('user_agent'):
            headers['User-Agent'] = self.source['user_agent']
        hosts = {urlsplit(url).hostname}
        if url == self.source['url']:
            hosts.update(urlsplit(u).hostname for u in self.source.get('fallback_urls', []))
        return self.fetcher.get(url, headers, allowed_hosts or hosts)


def collect_batch(source, checkpoint, fetcher, window=None, now=None):
    window = window or CollectionWindow()
    adapter = ADAPTERS.get(source['adapter'])
    is_web = source['adapter'] == 'telegram' and source.get('telegram_mode', 'mtproto') == 'web'
    if is_web:
        adapter = telegram_web.collect
    if not adapter:
        raise ValueError('unsupported source adapter')
    if source.get('retired'):
        raise ValueError('retired source; choose its replacement')
    urls = [source['url'], *source.get('fallback_urls', [])]
    for index, url in enumerate(urls):
        configured = {**source, 'url':url}
        # An ETag belongs to one feed endpoint, not all of its mirrors.
        cp = checkpoint if url == checkpoint.get('fetch_url', source['url']) else {}
        try:
            kwargs = {}
            if source['adapter'] in ('rss', 'nvd', 'nvidia') or is_web:
                kwargs['now'] = now or datetime.now(timezone.utc)
            if source['adapter'] == 'nvd' or is_web:
                kwargs['window'] = window
            result = adapter(configured, cp, SourceFetcher(fetcher, configured), **kwargs)
            batch = result if isinstance(result, CollectionBatch) else CollectionBatch(documents=result[0],checkpoint=result[1])
            if source['adapter'] != 'nvd' and not is_web:
                def in_window(doc):
                    date = doc.get('published_at')
                    if not date:
                        return not (window.date_from or window.date_to)
                    date = datetime.fromisoformat(date.replace('Z','+00:00'))
                    return (not window.date_from or date >= window.date_from) and (not window.date_to or date <= window.date_to)
                batch.documents = [d for d in batch.documents if in_window(d)]
                batch.coverage.update(kind='current_feed', historical_complete=False)
                if batch.checkpoint.get('next_url'):
                    batch.continuation = {k:batch.checkpoint[k] for k in ('next_url','until') if k in batch.checkpoint}
                    batch.coverage.update(kind='modified_window',partial=True)
            batch.coverage.update(source_id=source.get('id'), fetch_url=url)
            batch.counters.setdefault('fetched',len(batch.documents))
            if index or 'fetch_url' in checkpoint:
                batch.checkpoint['fetch_url'] = url
            return batch
        except (ValueError, httpx.HTTPError) as exc:
            if getattr(exc, 'retry_after', 0) or index == len(urls)-1:
                raise
    raise FetchError('source collection failed')
