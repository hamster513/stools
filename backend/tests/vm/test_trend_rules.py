import datetime as dt
from datetime import datetime, timedelta

from api.modules.vm.services.trends.rules import date, evaluate, extract_identifiers

NOW = datetime(2026, 11, 5, 12, tzinfo=dt.UTC)


def evidence(publisher='one', **changes):
    return {'publisher_id': publisher, 'published_at': (NOW-timedelta(days=1)).isoformat(),
            'text': 'Independent analysis by ' + publisher, 'url': 'https://' + publisher + '.test/article',
            'links': [], 'independent': True, **changes}


def test_two_independent_reports_but_not_reprints():
    assert evaluate([evidence(), evidence('two')], NOW)['active']
    same = [evidence(str(i), text='Original text', links=['https://original.test/report']) for i in range(10)]
    assert not evaluate(same, NOW)['active']


def test_exploitation_old_kev_poc_and_missing_dates():
    assert evaluate([evidence(evidence_kind='kev', exploitation_confirmed=True)], NOW)['active']
    assert not evaluate([evidence(evidence_kind='kev', exploitation_confirmed=True,
                                  published_at='2021-11-03T00:00:00Z', updated_at=NOW.isoformat())], NOW)['active']
    assert not evaluate([evidence(text='Exploit PoC available')], NOW)['active']
    assert not evaluate([evidence(published_at=None, exploitation_confirmed=True)], NOW)['active']


def test_retraction_and_untrusted_exploitation_flag():
    assert not evaluate([evidence(exploitation_confirmed=True)], NOW)['active']
    assert not evaluate([evidence(exploitation_confirmed=True, evidence_kind='kev', retracted=True)], NOW)['active']


def test_extract_multiple_identifiers():
    assert extract_identifiers('cve-2026-12345 and CVE-2026-23456 / CVE-2026-12345') == ['CVE-2026-12345', 'CVE-2026-23456']


def test_two_reports_expire_when_older_report_leaves_window():
    now = dt.datetime(2026, 11, 5, tzinfo=dt.UTC)
    evidence = [{'publisher_id': 'one', 'url': 'https://one.test/a', 'text': 'One independent report', 'independent': True,
                     'published_at': (now-dt.timedelta(days=6)).isoformat()},
                {'publisher_id': 'two', 'url': 'https://two.test/b', 'text': 'Other original report', 'independent': True,
                     'published_at': now.isoformat()}]
    result = evaluate(evidence, now)
    assert date(result['active_until']) == now + dt.timedelta(days=1)


def test_shared_vulnerability_reference_does_not_merge_news_publishers():
    reference = 'https://nvd.nist.gov/vuln/detail/CVE-2011-3402'
    rows = [evidence(name, links=[reference]) for name in ('one', 'two')]
    assert evaluate(rows, NOW)['independent_sources'] == 2


def test_direct_article_citation_and_same_publisher_are_one_chain():
    assert evaluate([evidence(), evidence('two', links=['https://one.test/article'])], NOW)['independent_sources'] == 1
    assert evaluate([evidence(url='https://one.test/a'), evidence(url='https://one.test/b', text='Different article')], NOW)['independent_sources'] == 1


def test_period_uses_publication_date_not_identifier_year_or_update_date():
    current = evidence(title='CVE-2011-3402 is exploited again')
    catalog = evidence('two', evidence_kind='kev', exploitation_confirmed=True,
                       published_at='2025-10-06T00:00:00Z', updated_at=NOW.isoformat())
    assert evaluate([current, catalog], NOW, period='7d')['publication_count'] == 1
    assert not evaluate([current, catalog], NOW, period='7d')['active']
    assert evaluate([catalog], NOW, period='all')['active']
    assert evaluate([catalog], NOW, period='all')['publication_count'] == 1


def test_today_and_custom_dates_use_timezone_and_inclusive_end_date():
    rows = [evidence(published_at='2026-11-04T21:30:00Z'), evidence('two', published_at='2026-11-04T20:59:59Z')]
    assert evaluate(rows, NOW, period='today', tz='Europe/Moscow')['publication_count'] == 1
    assert evaluate(rows, NOW, period='today', tz='UTC')['publication_count'] == 0
    result = evaluate(rows, NOW, period='custom', tz='Europe/Moscow', date_from='2026-11-04', date_to='2026-11-04')
    assert result['publication_count'] == 1
    assert result['last_event_at'] == '2026-11-04T20:59:59+00:00'


def test_rolling_periods_exclude_missing_future_rejected_and_retracted_dates():
    rows = [evidence(published_at=(NOW-timedelta(days=20)).isoformat()), evidence('two', published_at=None),
            evidence('three', published_at=(NOW+timedelta(seconds=1)).isoformat()), evidence('four', rejected=True),
            evidence('five', retracted=True)]
    assert evaluate(rows, NOW, period='7d')['publication_count'] == 0
    assert evaluate(rows, NOW, period='30d')['publication_count'] == 1
    assert evaluate(rows, NOW, period='all')['publication_count'] == 1


def test_article_query_identity_is_preserved_but_tracking_is_ignored():
    from api.modules.vm.services.trends.rules import canonical_url
    assert canonical_url('https://one.test/show/?i=123&utm_source=feed#top') == 'https://one.test/show?i=123'
    rows = [evidence('one', url='https://news.test/show/?i=123'),
            evidence('two', url='https://news.test/show/?i=456')]
    assert evaluate(rows, NOW)['independent_sources'] == 2


def test_generic_short_feed_content_does_not_merge_distinct_titles():
    rows = [evidence('one', text='Read more', title='First vulnerability investigation'),
            evidence('two', text='Read more', title='Second independent analysis')]
    assert evaluate(rows, NOW)['independent_sources'] == 2
