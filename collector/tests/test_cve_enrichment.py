from datetime import datetime, timezone
import httpx
from stools_threat_collector.enrichment import enrich_cve

NOW=datetime(2026,11,7,tzinfo=timezone.utc)
class Provider:
    def get(self,url):
        if 'cveawg' in url:
            return httpx.Response(200,request=httpx.Request('GET',url),json={'cveMetadata':{'datePublished':'2026-11-06T10:00:00Z'},'containers':{'cna':{
                'descriptions':[{'lang':'en','value':'CNA description'}],
                'metrics':[{'cvssV3_1':{'baseScore':9.8,'vectorString':'CVSS:3.1/example'}}],
                'affected':[{'vendor':'vendor','product':'server','versions':[{'version':'1.0','lessThan':'2.0','status':'affected'}]}]}}})
        raise httpx.ConnectError('provider unavailable')

def test_provider_failure_unknown_and_cna_fills_missing_nvd():
    result=enrich_cve('CVE-2026-12345',Provider(),now=NOW)
    assert result.cvss == 9.8 and result.provenance['cvss']=='cna'
    assert result.epss is None and result.known_exploited is None
    assert result.providers['nvd'].status=='error'
    assert result.providers['cna'].status=='ok'
    assert result.description=='CNA description'

def test_cached_result_avoids_network_and_metadata_is_not_news():
    old=enrich_cve('CVE-2026-12345',Provider(),now=NOW).model_dump(mode='json')
    class NoNetwork:
        def get(self,url): raise AssertionError('cached fetch')
    assert enrich_cve('CVE-2026-12345',NoNetwork(),previous=old,now=NOW).cvss==9.8
