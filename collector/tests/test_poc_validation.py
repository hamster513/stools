import base64
from datetime import datetime,timezone
import httpx
from stools_threat_collector.poc_validation import validate_poc
from stools_threat_collector.poc_search import search_poc_candidates

SHA='a'*40
class Github:
    def __init__(self, files): self.files=files; self.urls=[]
    def get(self,url,headers=None):
        self.urls.append(url)
        if '/repositories/' in url: data={'id':12,'full_name':'owner/CVE-2026-12345','default_branch':'main','parent':{'id':1}}
        elif '/commits/' in url: data={'sha':SHA}
        elif '/git/trees/' in url:
            assert SHA in url
            data={'tree':[{'type':'blob','path':p,'sha':str(i)*40,'size':len(t),'mode':'100644'} for i,(p,t) in enumerate(self.files.items(),1)]}
        elif '/git/blobs/' in url: data={'encoding':'base64','content':base64.b64encode(list(self.files.values())[int(url[-1])-1].encode()).decode()}
        elif '/search/' in url: data={'total_count':30,'items':[{'id':12,'full_name':'owner/CVE-2026-12345','html_url':'https://github.com/owner/CVE-2026-12345'}]}
        else: raise AssertionError(url)
        return httpx.Response(200,json=data,request=httpx.Request('GET',url))

def candidate(): return {'cve_id':'CVE-2026-12345','repository_id':12,'url':'https://github.com/owner/CVE-2026-12345'}

def test_repository_name_is_candidate_not_confirmation():
    r=search_poc_candidates('CVE-2026-12345',Github({}))
    assert r['candidates'][0]['state']=='candidate' and r['truncated']

def test_reproducer_and_instructions_promote_only_to_likely():
    files={'README.md':'CVE-2026-12345 proof of concept. Reproduce: python exploit.py TARGET',
           'exploit.py':'# CVE-2026-12345 payload\nimport requests\nrequests.post(target, data=payload)'}
    result=validate_poc(candidate(),Github(files))
    assert result.state=='likely' and result.commit_sha==SHA and result.family_id=='github:1'
    assert len(result.evidence)==2 and all(SHA in e.url for e in result.evidence)

def test_list_or_scanner_not_promoted():
    result=validate_poc(candidate(),Github({'README.md':'CVE-2026-12345 vulnerability scanner usage',
        'scanner.py':'import requests\nrequests.get(target)'}))
    assert result.state=='candidate'

def test_failure_preserves_previous_result():
    old=validate_poc(candidate(),Github({'README.md':'CVE-2026-12345'})).model_dump(mode='json')
    class Failed:
        def get(self,*a,**k): raise httpx.ConnectError('no network')
    result=validate_poc(candidate(),Failed(),previous=old)
    assert result.commit_sha==SHA and result.incomplete and result.error


def test_cve_prefix_is_not_exact_evidence():
    item={**candidate(),'cve_id':'CVE-2026-1234'}
    files={'README.md':'CVE-2026-12345 proof of concept. Reproduce: python exploit.py TARGET',
           'exploit.py':'import requests\nrequests.post(target,data=payload)'}
    result=validate_poc(item,Github(files))
    assert result.state=='candidate' and 'точная CVE в документации' not in result.signals


def test_shared_github_cooldown_honors_real_fetcher_429(monkeypatch):
    import pytest
    from stools_threat_collector import poc_search
    from stools_threat_collector.fetcher import Fetcher,FetchError
    monkeypatch.setattr(poc_search,'_quota_until',{})
    requests=[]
    def limited(request):
        requests.append(request);return httpx.Response(429,headers={'Retry-After':'7200'})
    fetcher=Fetcher(transport=httpx.MockTransport(limited),resolver=lambda _:['93.184.216.34'])
    for _ in range(2):
        with pytest.raises(FetchError): poc_search.github_get(fetcher,'https://api.github.com/repositories/12')
    assert len(requests)==1
