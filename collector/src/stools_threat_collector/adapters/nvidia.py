"""NVIDIA's official bulletin index (the publisher moved here in October 2026)."""
import re
from datetime import datetime, timezone
from urllib.parse import urljoin
import httpx
from .rss import identifiers, recent_publication

BASE = 'https://raw.githubusercontent.com/NVIDIA/product-security/main/'

def parse_index(text, year):
    rows=[]
    for line in text.splitlines():
        cells=[c.strip() for c in line.strip('| ').split('|')]
        if len(cells)!=5:
            continue
        match=re.fullmatch(r'\[(\d+)\]\((\d+/\d+\.md)\)',cells[0])
        if not match:
            continue
        try:
            published=datetime.strptime(cells[2],'%Y-%m-%d').replace(tzinfo=timezone.utc).isoformat()
            updated=datetime.strptime(cells[3],'%Y-%m-%d').replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
        path=f'{year}/{match[2]}'
        rows.append({'external_id':f'nvidia-{match[1]}','title':cells[1],
            'url':f'https://github.com/NVIDIA/product-security/blob/main/{path}',
            'raw_url':BASE+path,'published_at':published,'updated_at':updated,
            'text':cells[1]+' '+cells[4],'identifiers':identifiers(cells[4]),
            'links':[],'full_text':False,'truncated':False})
    if not rows:
        raise ValueError('NVIDIA bulletin index not recognized')
    return rows

def collect(source, checkpoint, fetcher, now=None):
    now=now or datetime.now(timezone.utc)
    if source['url']!='https://github.com/NVIDIA/product-security':
        raise ValueError('NVIDIA official repository required')
    docs=[]
    # Previous year is necessary around New Year; no GitHub API quota is consumed.
    years=[now.year,now.year-1] if now.month==1 else [now.year]
    for year in years:
        try:
            response=fetcher.get(BASE+f'{year}/README.md')
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code==404 and now.month==1:
                continue
            raise
        rows=parse_index(response.text,year)
        for row in rows:
            if not recent_publication(row['published_at'],now):
                continue
            raw=row.pop('raw_url')
            row['links']=[row['url']]
            # Index already supplies title, CVEs and original date; body is optional.
            try:
                body=fetcher.get(raw).text
                row.update(text=body[:262144],full_text=True,truncated=len(body)>262144)
            except (httpx.HTTPError,ValueError):
                pass
            docs.append(row)
    return docs,{}
