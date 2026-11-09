"""Repository search is a discovery signal, never proof of exploitability."""
import os
import re
import time
import threading
from pathlib import Path
from urllib.parse import urlencode
import httpx
from .fetcher import FetchError
from .monitoring_contracts import PocCandidate


_quota_lock = threading.Lock()
_quota_until = {}


def github_get(fetcher,url):
    if not url.startswith('https://api.github.com/'):
        raise ValueError('GitHub API URL required')
    bucket='search' if '/search/' in url else 'core'
    with _quota_lock:
        until=_quota_until.get(bucket,0)
    if until>time.time(): raise FetchError('GitHub quota waiting',int(until-time.time())+1)
    headers={'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'}
    token_file=os.environ.get('COLLECTOR_GITHUB_TOKEN_FILE')
    if token_file:
        headers['Authorization']='Bearer '+Path(token_file).read_text().strip()
    try:
        response=fetcher.get(url,headers); response.raise_for_status()
        if response.headers.get('x-ratelimit-remaining')=='0':
            reset=response.headers.get('x-ratelimit-reset','')
            with _quota_lock: _quota_until[bucket]=int(reset) if reset.isdigit() else time.time()+900
        return response.json()
    except FetchError as exc:
        if exc.retry_after:
            with _quota_lock: _quota_until[bucket]=time.time()+exc.retry_after
        raise
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code in (403,429):
            reset=exc.response.headers.get('x-ratelimit-reset','')
            retry=exc.response.headers.get('retry-after','')
            delay=max(60,int(retry) if retry.isdigit() else 0,int(reset)-int(time.time())+5 if reset.isdigit() else 900)
            with _quota_lock: _quota_until[bucket]=time.time()+delay
            raise FetchError('GitHub quota or access denied',delay) from exc
        raise


def search_poc_candidates(cve_id,fetcher,page=1):
    if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cve_id):
        raise ValueError('CVE identifier required')
    data=github_get(fetcher,'https://api.github.com/search/repositories?'+urlencode({
        'q':f'{cve_id} in:name,description fork:true','per_page':20,'page':page}))
    if not isinstance(data.get('items'),list): raise ValueError('invalid GitHub search result')
    rows=sorted(data['items'],key=lambda r:bool(r.get('fork')))
    candidates=[]
    for row in rows[:20]:
        name=row.get('full_name','')
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',name): continue
        candidates.append(PocCandidate(cve_id=cve_id,repository_id=row['id'],repository_name=name,
            url='https://github.com/'+name,reason='CVE найдена в имени или описании репозитория; нужна проверка').model_dump(mode='json'))
    truncated=data.get('total_count',0)>page*20 or bool(data.get('incomplete_results'))
    return {'candidates':candidates,'continuation':{'page':page+1} if data.get('total_count',0)>page*20 and page<50 else None,
            'provider_status':'ok','truncated':truncated,'total':data.get('total_count',0)}
