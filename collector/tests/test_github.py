from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from stools_threat_collector.adapters import github
from stools_threat_collector.contracts import Source

SOURCE = {'url': 'https://api.github.com/advisories'}
NOW = datetime(2026, 11, 6, tzinfo=timezone.utc)


def advisory(**changes):
    return {'ghsa_id': 'GHSA-abcd-1234-efgh', 'cve_id': 'CVE-2024-12345',
            'html_url': 'https://github.com/advisories/GHSA-abcd-1234-efgh',
            'summary': 'Affected package', 'description': 'Research and remediation',
            'published_at': '2024-01-01T00:00:00Z', 'updated_at': '2026-11-05T00:00:00Z',
            'withdrawn_at': None, 'references': ['https://vendor.example/advisory'],
            'identifiers': [{'type': 'CVE', 'value': 'CVE-2024-12345'}], **changes}


class Fetch:
    def __init__(self, pages):
        self.pages = iter(pages)
        self.urls = []

    def get(self, url, headers=None):
        self.urls.append(url)
        result = next(self.pages)
        if isinstance(result, Exception):
            raise result
        payload, next_url = result
        response_headers = {'Link': f'<{next_url}>; rel="next"'} if next_url else {}
        return httpx.Response(200, json=payload, headers=response_headers, request=httpx.Request('GET', url))


def test_github_preserves_original_dates_ids_and_withdrawal():
    doc = github.parse_advisory(advisory(withdrawn_at='2026-11-05T00:00:00Z'))
    assert doc['published_at'] == '2024-01-01T00:00:00Z'
    assert doc['updated_at'] == '2026-11-05T00:00:00Z'
    assert set(doc['identifiers']) == {'CVE-2024-12345', 'GHSA-abcd-1234-efgh'}
    assert doc['retracted'] is True
    assert doc.get('exploitation_confirmed', False) is False
    assert doc['links'] == ['https://vendor.example/advisory']


def test_github_pagination_resumes_then_advances_fixed_window():
    next_url = SOURCE['url'] + '?type=reviewed&after=abc'
    fetch = Fetch([([advisory()], next_url)])
    docs, checkpoint = github.collect(SOURCE, {}, fetch, now=NOW, max_pages=1)
    assert len(docs) == 1
    query = parse_qs(urlsplit(fetch.urls[0]).query)
    assert query['type'] == ['reviewed']
    assert query['sort'] == ['updated'] and query['direction'] == ['asc']
    assert query['modified'] == ['2026-10-07T00:00:00Z..2026-11-06T00:00:00Z']
    assert checkpoint['next_url'] == next_url
    followup = Fetch([([], None)])
    _, finished = github.collect(SOURCE, checkpoint, followup, now=NOW)
    assert followup.urls == [next_url]
    assert 'next_url' not in finished and finished['since'] == '2026-11-06T00:00:00Z'
    again = Fetch([([], None)])
    github.collect(SOURCE, finished, again, now=NOW)
    assert parse_qs(urlsplit(again.urls[0]).query)['modified'][0].startswith('2026-11-05T00:00:00Z..')


def test_github_mid_page_failure_does_not_advance_input_checkpoint():
    original = {'since': '2026-11-04T00:00:00Z'}
    next_url = SOURCE['url'] + '?after=abc'
    fetch = Fetch([([advisory()], next_url), RuntimeError('rate limited')])
    with pytest.raises(RuntimeError, match='rate limited'):
        github.collect(SOURCE, original, fetch, now=NOW)
    assert original == {'since': '2026-11-04T00:00:00Z'}


@pytest.mark.parametrize('url', ['https://other.example/advisories', 'http://api.github.com/advisories',
                                 'https://api.github.com/repos/private', 'https://user:secret@api.github.com/advisories'])
def test_github_rejects_cross_origin_or_wrong_path_pagination(url):
    fetch = Fetch([([], url)])
    with pytest.raises(ValueError, match='GitHub advisory URL'):
        github.collect(SOURCE, {}, fetch, now=NOW)
    assert len(fetch.urls) == 1


def test_github_rejects_invalid_payload_and_supports_source_contract():
    source = Source(name='GitHub advisories', publisher_id='microsoft', adapter='github', **SOURCE)
    assert source.adapter == 'github'
    with pytest.raises(ValueError):
        github.collect(SOURCE, {}, Fetch([({'message': 'error'}, None)]), now=NOW)
    with pytest.raises(ValueError):
        github.parse_advisory(advisory(ghsa_id=''))


def test_github_rate_limit_waits_until_server_reset():
    import time
    from stools_threat_collector.fetcher import FetchError
    response = httpx.Response(403, headers={'X-RateLimit-Remaining': '0',
                              'X-RateLimit-Reset': str(int(time.time()) + 600)},
                              request=httpx.Request('GET', SOURCE['url']))
    error = httpx.HTTPStatusError('rate limit', request=response.request, response=response)
    with pytest.raises(FetchError, match='GitHub API rate limit') as caught:
        github.collect(SOURCE, {}, Fetch([error]), now=NOW)
    assert 590 <= caught.value.retry_after <= 605


def test_github_non_rate_http_error_has_actionable_status():
    from stools_threat_collector.fetcher import FetchError
    response = httpx.Response(422, request=httpx.Request('GET', SOURCE['url']))
    error = httpx.HTTPStatusError('invalid query', request=response.request, response=response)
    with pytest.raises(FetchError, match='GitHub API HTTP 422'):
        github.collect(SOURCE, {}, Fetch([error]), now=NOW)
