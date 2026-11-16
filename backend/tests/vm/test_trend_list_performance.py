from collections import Counter

from sqlalchemy import event, select

from api.modules.vm.services.trends import analyze, query
from api.modules.vm.services.trends.ingest import apply_page
from api.modules.vm.trend_models import (
    VmTrendCard,
    VmTrendEvidence,
    VmTrendPolicy,
    VmTrendPublication,
    VmTrendSource,
)
from tests.vm.test_trends_api import news_page


def seed(db, count=125):
    apply_page(db, news_page([
        {'identifiers': [f'CVE-2026-{20000+i}'], 'title': f'Security issue CVE-2026-{20000+i}'}
        for i in range(count)
    ]))
    analyze.process_pending(db)


def test_mentions_discard_non_identifiers_before_loading_evidence(db_session, monkeypatch):
    seed(db_session, 1)
    publication = db_session.scalar(select(VmTrendPublication).limit(1))
    db_session.add(VmTrendCard(id='signal-example', title='Background story'))
    db_session.flush()
    db_session.add(VmTrendEvidence(card_id='signal-example', publication_id=publication.id))
    db_session.commit()
    original = query.evidence_for
    loaded = []
    def capture(db, ids, *args, **kwargs):
        loaded.extend(ids)
        return original(db, ids, *args, **kwargs)
    monkeypatch.setattr(query, 'evidence_for', capture)
    result = query.list_cards(db_session, view='mentions', sort='date')
    assert result['total'] == 1
    assert loaded == ['CVE-2026-20000']


def test_lookup_queries_do_not_multiply_with_evidence_batches(db_session):
    seed(db_session)
    counts = Counter()
    def record(conn, cursor, statement, *args):
        for name in ('vm_trend_source', 'vm_trend_policy'):
            if f'FROM {name}' in statement and 'vm_trend_card' not in statement:
                counts[name] += 1
    engine = db_session.get_bind()
    event.listen(engine, 'before_cursor_execute', record)
    try:
        result = query.list_cards(db_session, view='mentions', sort='date', limit=10, offset=100)
    finally:
        event.remove(engine, 'before_cursor_execute', record)
    assert result['total'] == 125 and len(result['items']) == 10
    assert counts == {'vm_trend_source': 1, 'vm_trend_policy': 1}


def test_no_fingerprint_work_without_matching_publication_decisions(db_session, monkeypatch):
    seed(db_session, 1)
    def unexpected(_):
        raise AssertionError('No publication decision requires a content fingerprint')
    monkeypatch.setattr(analyze, 'publication_fingerprint', unexpected)
    assert query.list_cards(db_session, view='mentions')['total'] == 1


def test_lookup_context_is_fresh_for_each_request(db_session):
    seed(db_session, 1)
    assert query.list_cards(db_session, view='mentions')['items'][0]['source_name'] == 'publisher-0'
    source = db_session.scalar(select(VmTrendSource).limit(1))
    source.data = {**source.data, 'name': 'Changed publisher'}
    db_session.commit()
    assert query.list_cards(db_session, view='mentions')['items'][0]['source_name'] == 'Changed publisher'
    db_session.add(VmTrendPolicy(scope='cve_global', target_key='CVE-2026-20000', reason='Exclude reviewed issue', enabled=True, actor='test', history=[]))
    db_session.commit()
    assert query.list_cards(db_session, view='mentions')['total'] == 0


def test_mentions_sql_filter_preserves_identifier_variants(db_session):
    from api.modules.vm.services.trends.rules import extract_identifiers
    seed(db_session, 1)
    publication = db_session.scalar(select(VmTrendPublication).limit(1))
    identifiers = ['GHSA-ABCD-EFGH-2345', 'BDU:2026-123', 'BDU-2026:456',
                   'cve-2026-12345', 'prefix-CVE-2026-12345', 'CVE-2026-12345\n',
                   'CVE-2026-12345 and CVE-2026-23456', 'signal-none']
    for identifier in identifiers:
        db_session.add(VmTrendCard(id=identifier, title='Security report'))
    db_session.flush()
    for identifier in identifiers:
        db_session.add(VmTrendEvidence(card_id=identifier, publication_id=publication.id))
    db_session.commit()
    result = query.list_cards(db_session, view='mentions', sort='identifier')
    expected = {'CVE-2026-20000', *(i for i in identifiers if extract_identifiers(i) == [i])}
    assert {item['id'] for item in result['items']} == expected


def test_stale_review_revision_does_not_hash_current_content(db_session, monkeypatch):
    from api.modules.vm.trend_models import VmTrendReview
    seed(db_session, 1)
    publication = db_session.scalar(select(VmTrendPublication).limit(1))
    db_session.add(VmTrendReview(card_id='CVE-2026-20000', actor='test', decision={
        'publication_key': publication.external_id, 'revision': publication.revision + 1,
        'fingerprint': 'old', 'independent': False,
    }))
    db_session.commit()
    def unexpected(_):
        raise AssertionError('Review revision does not match current publication')
    monkeypatch.setattr(analyze, 'publication_fingerprint', unexpected)
    assert query.list_cards(db_session, view='mentions')['items'][0]['independent_sources'] == 1


def test_shared_publication_hash_is_reused_but_decisions_are_per_card(db_session, monkeypatch):
    from api.modules.vm.trend_models import VmTrendReview
    seed(db_session, 1)
    publication = db_session.scalar(select(VmTrendPublication).limit(1))
    second = 'CVE-2026-20001'
    db_session.add(VmTrendCard(id=second, title='Same publication, another vulnerability'))
    db_session.flush()
    db_session.add(VmTrendEvidence(card_id=second, publication_id=publication.id))
    fingerprint = analyze.publication_fingerprint(publication.data)
    for identifier, independent in [('CVE-2026-20000', False), (second, True)]:
        db_session.add(VmTrendReview(card_id=identifier, actor='test', decision={
            'publication_key': publication.external_id, 'revision': publication.revision,
            'fingerprint': fingerprint, 'independent': independent,
        }))
    db_session.commit()
    original = analyze.publication_fingerprint
    calls = []
    def capture(value):
        calls.append(1)
        return original(value)
    monkeypatch.setattr(analyze, 'publication_fingerprint', capture)
    result = query.list_cards(db_session, view='mentions')
    assert {row['id']: row['independent_sources'] for row in result['items']} == {'CVE-2026-20000': 0, second: 1}
    assert len(calls) == 1


def test_date_page_matches_only_relevant_tie_groups_and_keeps_risk_order(db_session, monkeypatch):
    import datetime as dt

    from api.modules.vm.models import VmCve, VmHost, VmHostCve
    now = dt.datetime.now(dt.UTC)
    rows = [{'identifiers': [f'CVE-2026-{30000+i}'], 'title': f'Security issue CVE-2026-{30000+i}',
             'published_at': (now-dt.timedelta(days=i//10)).isoformat()} for i in range(30)]
    apply_page(db_session, news_page(rows))
    analyze.process_pending(db_session)
    host = VmHost(hostname='fixture', ip='192.0.2.1')
    db_session.add(host)
    db_session.add_all([VmCve(cve_id=f'CVE-2026-{30000+i}') for i in range(30)])
    db_session.flush()
    db_session.add_all([VmHostCve(host_id=host.id, cve_id=f'CVE-2026-{30000+i}', risk=i+1, risk_raw=(i+1)/100) for i in range(30)])
    db_session.commit()
    original = query.match_aggregates
    matched = []
    def capture(ids):
        matched.extend(ids)
        return original(ids)
    monkeypatch.setattr(query, 'match_aggregates', capture)
    result = query.list_cards(db_session, view='mentions', sort='date', offset=8, limit=3)
    assert [row['id'] for row in result['items']] == ['CVE-2026-30001', 'CVE-2026-30000', 'CVE-2026-30019']
    assert all(row['hosts'] == 1 and row['risk'] > 0 for row in result['items'])
    assert result['total'] == 30
    assert set(matched) == {f'CVE-2026-{30000+i}' for i in range(20)}
