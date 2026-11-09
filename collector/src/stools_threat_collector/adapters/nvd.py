"""NVD 2.0: fixed last-modified windows, one bounded page per run."""
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from ..monitoring_contracts import CollectionBatch, CollectionWindow


def iso(value):
    if not value:
        return None
    date = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return date.replace(tzinfo=date.tzinfo or timezone.utc).astimezone(timezone.utc).isoformat()


def collect(source, checkpoint, fetcher, window=None, now=None):
    now = now or datetime.now(timezone.utc)
    window = window or CollectionWindow()
    progress = checkpoint.get('nvd_progress')
    if not progress:
        start = window.date_from or datetime.fromisoformat(checkpoint.get('last_complete') or (now-timedelta(days=30)).isoformat())
        end = window.date_to or now
        progress = {'from': start.isoformat(), 'until': end.isoformat(), 'end': min(end, start+timedelta(days=120)).isoformat(), 'index':0}
    parts = urlsplit(source['url'])
    params = dict(parse_qsl(parts.query))
    params.update(lastModStartDate=progress['from'], lastModEndDate=progress['end'],
                  startIndex=str(progress['index']), resultsPerPage='200')
    response = fetcher.get(urlunsplit(parts._replace(query=urlencode(params))))
    data = response.json()
    if not isinstance(data.get('vulnerabilities'), list) or data.get('startIndex') != progress['index']:
        raise ValueError('NVD response or pagination invalid')
    docs = []
    for row in data['vulnerabilities']:
        cve = row['cve']; identifier = cve['id']
        text = next((d['value'] for d in cve.get('descriptions', []) if d['lang']=='en'), '')
        docs.append({'external_id':identifier,'title':identifier,'url':f'https://nvd.nist.gov/vuln/detail/{identifier}',
            'text':text,'identifiers':[identifier], 'published_at':iso(cve.get('published')),
            'updated_at':iso(cve.get('lastModified')), 'links':[r['url'] for r in cve.get('references', [])][:100],
            'full_text':True, 'date_basis':'published' if cve.get('published') else 'unknown'})
    next_index = progress['index'] + len(data['vulnerabilities'])
    total = data.get('totalResults')
    if not isinstance(total, int) or (not docs and next_index < total):
        raise ValueError('NVD incomplete page')
    cp = dict(checkpoint)
    if next_index < total:
        progress = {**progress, 'index':next_index}
    elif progress['end'] < progress['until']:
        start = datetime.fromisoformat(progress['end'])
        progress = {**progress, 'from':progress['end'], 'end':min(datetime.fromisoformat(progress['until']),start+timedelta(days=120)).isoformat(), 'index':0}
    else:
        cp['last_complete'] = progress['until']; progress = None
    if progress:
        cp['nvd_progress'] = progress
    else:
        cp.pop('nvd_progress', None)
    return CollectionBatch(documents=docs, checkpoint=cp, continuation=progress,
        counters={'fetched':len(docs)}, coverage={'kind':'modified_window','total':total,'partial':bool(progress)})
