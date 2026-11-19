"""Read public previews only. A missing post in a page is never a retraction."""
import random
import time
from datetime import datetime, timedelta, timezone
from .telegram_public import normalize_channel, parse_posts as parse_public_posts
from .rss import identifiers
from ..monitoring_contracts import CollectionBatch, CollectionWindow


def parse_posts(html, channel):
    docs = parse_public_posts(html, channel)
    for doc in docs:
        doc['identifiers'] = identifiers(doc['text'], *doc['links'])
    return docs


def collect(source, checkpoint, fetcher, window=None, now=None):
    channel = normalize_channel(source.get('telegram_channel') or source['url'])
    now = now or datetime.now(timezone.utc); window = window or CollectionWindow()
    progress = checkpoint.get('telegram_progress')
    if not progress:
        progress = {'before':None, 'high':checkpoint.get('last_id',0), 'stop_id':checkpoint.get('last_id',0),
            'established':bool(checkpoint.get('last_id')),
            'cutoff':(window.date_from or (window.date_to or now)-timedelta(days=7 if checkpoint.get('last_id') else 30)).isoformat(),
            'until':(window.date_to or now).isoformat()}
    docs = []; complete = False
    for page in range(3):
        if page:
            time.sleep(random.uniform(2,5))
        url = f'https://t.me/s/{channel}' + (f'?before={progress["before"]}' if progress['before'] else '')
        rows = parse_posts(fetcher.get(url).content, channel)
        if not rows:
            complete = True; break
        ids = [int(r['external_id']) for r in rows]
        progress['high'] = max(progress['high'],max(ids))
        minimum = min(ids)
        if progress['before'] and minimum >= progress['before']:
            raise ValueError('Telegram pagination did not advance')
        for doc in rows:
            date = doc['published_at']
            # Read edits within the overlap; also catch every newer ID after long outages.
            in_range = not date or datetime.fromisoformat(progress['cutoff']) <= datetime.fromisoformat(date) <= datetime.fromisoformat(progress['until'])
            catchup = progress.get('established', bool(progress['stop_id'])) and not window.date_from and not window.date_to and int(doc['external_id']) > progress['stop_id']
            if (in_range or catchup) and (not date or datetime.fromisoformat(date) <= datetime.fromisoformat(progress['until'])):
                docs.append(doc)
            if date and datetime.fromisoformat(date) < datetime.fromisoformat(progress['cutoff']) and (not progress.get('established', bool(progress['stop_id'])) or int(doc['external_id']) <= progress['stop_id']):
                complete = True
        progress['before'] = minimum
        if minimum <= 1:
            complete = True
        if complete:
            break
    cp = dict(checkpoint)
    if complete:
        cp['last_id'] = progress['high']; cp.pop('telegram_progress',None)
    else:
        cp['telegram_progress'] = progress
    return CollectionBatch(documents=docs,checkpoint=cp,continuation=None if complete else progress,
        counters={'fetched':len(docs)},coverage={'kind':'public_preview','partial':not complete,
            'from':progress['cutoff'],'to':progress['until'],'deletions_checked':False})
