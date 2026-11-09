"""Read public previews only. A missing post in a page is never a retraction."""
import random
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from bs4 import BeautifulSoup
from .rss import identifiers
from ..monitoring_contracts import CollectionBatch, CollectionWindow


def normalize_channel(value):
    if value.startswith(('https://','http://')):
        parts = urlsplit(value)
        if parts.hostname != 't.me' or parts.query or parts.fragment:
            raise ValueError('public Telegram channel required')
        value = parts.path.removeprefix('/s/').strip('/')
    value = value.lstrip('@')
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{3,31}', value):
        raise ValueError('public Telegram channel required')
    return value.lower()


def parse_posts(html, channel):
    soup = BeautifulSoup(html, 'html.parser')
    posts = soup.select('.tgme_widget_message[data-post]')
    if not posts and not soup.select_one('.tgme_channel_history'):
        raise ValueError('Telegram public preview unavailable or layout changed')
    docs = []
    for post in posts:
        identity = post.get('data-post','').split('/')
        if len(identity)!=2 or identity[0].lower()!=channel or not identity[1].isdigit():
            continue
        date_node = post.select_one('.tgme_widget_message_date time[datetime]')
        date = None
        if date_node:
            try:
                date = datetime.fromisoformat(date_node['datetime'].replace('Z','+00:00'))
                date = date.astimezone(timezone.utc).isoformat() if date.tzinfo else None
            except ValueError:
                date = None
        for nested in post.select('.tgme_widget_message_reply, script, style'):
            nested.decompose()
        body = post.select_one('.tgme_widget_message_text')
        text = body.get_text(' ', strip=True) if body else ''
        links = sorted({a['href'] for a in post.select('.tgme_widget_message_text a[href], .tgme_widget_message_forwarded_from[href]')
                        if a['href'].startswith(('http://','https://'))})[:100]
        docs.append({'external_id':identity[1], 'url':f'https://t.me/{channel}/{identity[1]}',
            'title':text[:2000], 'text':text[:262144], 'published_at':date,
            'date_basis':'published' if date else 'unknown', 'links':links,
            'identifiers':identifiers(text,*links), 'full_text':True, 'truncated':len(text)>262144})
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
