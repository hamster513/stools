"""Deployment-owned secrets; callers see profile readiness, never proxy credentials."""
import json
import os
from pathlib import Path
from .fetcher import Fetcher


def profiles():
    path=os.environ.get('COLLECTOR_OUTBOUND_PROFILES_FILE')
    return json.loads(Path(path).read_text()) if path else {}


def route(name):
    required=os.environ.get('COLLECTOR_REQUIRE_PROXY','').lower() in ('true','1')
    if name=='inherit': proxy=os.environ.get('COLLECTOR_HTTP_PROXY');ca=os.environ.get('COLLECTOR_CA_FILE')
    elif name=='direct': proxy=None;ca=os.environ.get('COLLECTOR_CA_FILE')
    else:
        profile=profiles().get(name)
        if profile is None: raise ValueError('outbound profile unavailable')
        path=profile.get('proxy_url_file');proxy=Path(path).read_text().strip() if path else None
        ca=profile.get('ca_file')
        if profile.get('required',True) and not proxy: raise ValueError('required proxy unavailable')
    if required and not proxy: raise ValueError('direct access forbidden: configure required proxy')
    return proxy,ca


def make_fetcher(source=None):
    proxy,ca=route((source or {}).get('proxy_profile','inherit'))
    fetcher = Fetcher(proxy=proxy,ca=ca)
    from urllib.parse import urlsplit
    # Additional trust applies only to BDU source jobs, never the system store.
    if urlsplit((source or {}).get('url', '')).hostname == 'bdu.fstec.ru':
        fetcher.context.load_verify_locations(cafile=Path(__file__).with_name('certificates') / 'bdu-ca.pem')
    return fetcher


def public_profiles():
    result=[]
    for name in ['inherit','direct',*profiles()]:
        try:
            proxy,ca=route(name)
            if ca and not Path(ca).is_file(): raise ValueError('CA missing')
            result.append({'name':name,'ready':True,'route':'proxy' if proxy else 'direct','ca_configured':bool(ca)})
        except Exception:
            result.append({'name':name,'ready':False,'error':'Профиль или доверенный CA недоступен'})
    return result
