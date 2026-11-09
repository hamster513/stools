"""Fetch public CVE context. Inventory never enters these provider requests."""
from datetime import datetime, timedelta, timezone
from .monitoring_contracts import CveEnrichment, ProviderStatus
from .adapters.nvd import iso


def cpe_ranges(configurations):
    result=[]
    def walk(node, simple=True):
        simple = simple and node.get('operator','OR')=='OR' and not node.get('negate',False)
        for match in node.get('cpeMatch',[]):
            parts=match.get('criteria','').split(':')
            if len(parts)<6 or not match.get('vulnerable',False): continue
            result.append({**match,'vendor':parts[3],'product':parts[4],'version':parts[5],
                'ecosystem':'generic','complete':simple and not any('\\' in p for p in parts), 'provider':'nvd'})
        for child in node.get('nodes',[]) + node.get('children',[]): walk(child,simple)
    for config in configurations: walk(config)
    return result[:2000]


def enrich_cve(cve_id, fetcher, previous=None, now=None):
    now=now or datetime.now(timezone.utc)
    previous=previous or {}
    if previous.get('expires_at') and datetime.fromisoformat(previous['expires_at'].replace('Z','+00:00'))>now:
        return CveEnrichment.model_validate(previous)
    data={**previous,'cve_id':cve_id,'fetched_at':now,'providers':dict(previous.get('providers',{})),
          'provenance':dict(previous.get('provenance',{}))}
    data.setdefault('references',[])
    urls={'nvd':f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}',
          'cna':f'https://cveawg.mitre.org/api/cve/{cve_id}',
          'epss':f'https://api.first.org/data/v1/epss?cve={cve_id}'}
    for provider,url in urls.items():
        old_status=previous.get('providers',{}).get(provider,{})
        expiry=old_status.get('expires_at')
        if expiry and datetime.fromisoformat(expiry.replace('Z','+00:00'))>now:
            continue
        try:
            response=fetcher.get(url); response.raise_for_status(); body=response.json()
            found=True
            if provider=='nvd':
                rows=body.get('vulnerabilities',[]); found=bool(rows)
                if found:
                    cve=rows[0]['cve']; data['published_at']=iso(cve.get('published'))
                    metrics=cve.get('metrics',{})
                    metric=next((m['cvssData'] for key in ('cvssMetricV40','cvssMetricV31','cvssMetricV30','cvssMetricV2') for m in metrics.get(key,[]) if m.get('cvssData')),None)
                    if metric:
                        data.update(cvss=metric.get('baseScore'),cvss_vector=metric.get('vectorString',''))
                        data['provenance']['cvss']='nvd'
                    text=next((d['value'] for d in cve.get('descriptions',[]) if d['lang']=='en'), '')
                    if text: data['description']=text[:16000]; data['provenance']['description']='nvd'
                    ranges=cpe_ranges(cve.get('configurations',[]))
                    if ranges: data['cpe_matches']=ranges; data['provenance']['cpe_matches']='nvd'
                    if cve.get('cisaExploitAdd'): data['known_exploited']=True; data['provenance']['known_exploited']='nvd_cisa'
                    data['references']=list(dict.fromkeys(data['references']+[r['url'] for r in cve.get('references',[]) if r.get('url','').startswith(('http://','https://'))]))[:100]
            elif provider=='cna':
                cna=body.get('containers',{}).get('cna',{}); found=bool(cna)
                if not data.get('published_at'): data['published_at']=iso(body.get('cveMetadata',{}).get('datePublished'))
                if data.get('cvss') is None:
                    metric=next((m[key] for m in cna.get('metrics',[]) for key in ('cvssV4_0','cvssV3_1','cvssV3_0','cvssV2_0') if key in m),None)
                    if metric: data.update(cvss=metric.get('baseScore'),cvss_vector=metric.get('vectorString','')); data['provenance']['cvss']='cna'
                if not data.get('description'):
                    data['description']=next((d['value'] for d in cna.get('descriptions',[]) if d['lang']=='en'),'')[:16000]
                    if data['description']: data['provenance']['description']='cna'
                products=[]; ranges=[]
                for affected in cna.get('affected',[]):
                    product=affected.get('product',''); vendor=affected.get('vendor','')
                    products.append(product)
                    for version in affected.get('versions',[]):
                        if version.get('status')!='affected': continue
                        r={'vendor':vendor,'product':product,'ecosystem':affected.get('packageName') and affected.get('collectionURL','') or 'generic',
                           'complete':False,'provider':'cna','version':version.get('version','*')}
                        if version.get('lessThan') or version.get('lessThanOrEqual'):
                            r.pop('version'); r['versionStartIncluding']=version.get('version','')
                            r['versionEndExcluding' if version.get('lessThan') else 'versionEndIncluding']=version.get('lessThan') or version['lessThanOrEqual']
                        ranges.append(r)
                if products: data['affected_products']=list(dict.fromkeys(products))[:200]
                if not data.get('cpe_matches') and ranges: data['cpe_matches']=ranges[:2000]; data['provenance']['cpe_matches']='cna'
            else:
                rows=body.get('data',[]); found=bool(rows)
                if found:
                    data.update(epss=float(rows[0]['epss']),epss_percentile=float(rows[0]['percentile']))
                    data['provenance']['epss']='first'
            data['providers'][provider]=ProviderStatus(status='ok' if found else 'not_found',fetched_at=now,
                expires_at=now+timedelta(hours=24 if provider=='epss' else 1),url=url).model_dump(mode='json')
        except Exception as exc:  # Provider isolation; old values retain their provenance and stale timestamps.
            code=getattr(getattr(exc,'response',None),'status_code',None)
            delay=max(300,int(getattr(exc,'retry_after',0)))
            data['providers'][provider]=ProviderStatus(status='not_found' if code==404 else 'rate_limited' if code in (403,429) or getattr(exc,'retry_after',0) else 'error',
                fetched_at=now,expires_at=now+timedelta(seconds=delay),url=url,error=type(exc).__name__).model_dump(mode='json')
    published=data.get('published_at'); published=datetime.fromisoformat(published.replace('Z','+00:00')) if isinstance(published,str) else published
    ttl=timedelta(hours=24 if published and now-published>timedelta(days=7) else 1)
    expiry=min([datetime.fromisoformat(s['expires_at'].replace('Z','+00:00')) for s in data['providers'].values() if s.get('expires_at')]+[now+ttl])
    data['expires_at']=expiry
    return CveEnrichment.model_validate(data)
