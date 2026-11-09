import datetime as dt

from api.modules.vm.models import VmCve, VmHost, VmHostCve
from api.modules.vm.services.trends.analyze import process_pending
from api.modules.vm.services.trends.ingest import apply_page
from tests.vm.test_trend_sync import page


def test_settings_secrets_and_catalog(auth_client):
    response = auth_client.put('/api/vm/trends/settings', json={
        'url': 'https://collector.example.test:8443', 'token': 'do-not-return',
        'proxy_enabled': True, 'proxy_host': 'proxy.example.test', 'proxy_port': 3128, 'proxy_password': 'proxy-secret'})
    assert response.status_code == 200, response.text
    assert 'do-not-return' not in response.text and 'proxy-secret' not in response.text
    assert response.json()['token_set']
    changed = auth_client.put('/api/vm/trends/settings', json={'url': 'https://elsewhere.test'})
    assert changed.status_code == 422
    schedules = auth_client.get('/api/settings/schedules').json()['items']
    assert any(row['kind'] == 'trends_pull' for row in schedules)


def test_trend_matches_next_local_import_and_review(auth_client, db_session):
    data = page()
    data['events'][1]['payload']['published_at'] = dt.datetime.now(dt.UTC).isoformat()
    apply_page(db_session, data)
    process_pending(db_session)
    response = auth_client.get('/api/vm/trends?view=all')
    assert response.status_code == 200, response.text
    assert response.json()['total'] == 1
    assert auth_client.get('/api/vm/trends').json()['total'] == 0
    db_session.add(VmCve(cve_id='CVE-2026-12345'))
    host = VmHost(hostname='test.example', ip='192.0.2.1')
    db_session.add(host)
    db_session.flush()
    db_session.add(VmHostCve(host_id=host.id, cve_id='CVE-2026-12345', risk=90, risk_raw=0.9))
    db_session.commit()
    assert auth_client.get('/api/vm/trends').json()['total'] == 1
    detail = auth_client.get('/api/vm/trends/CVE-2026-12345').json()
    assert detail['matches']['hosts'][0]['hostname'] == 'test.example'
    review = auth_client.patch('/api/vm/trends/CVE-2026-12345/review', json={'version': detail['version'], 'status': 'verified'})
    assert review.status_code == 200, review.text
    assert auth_client.patch('/api/vm/trends/CVE-2026-12345/review', json={'version': detail['version'], 'status': 'rejected'}).status_code == 409


def test_manual_identity_and_decision_survive_full_replay(auth_client, db_session):
    data = page()
    pub = data['events'][1]['payload']
    pub.update(title='Early product signal', identifiers=[], text='Original research without identifier')
    apply_page(db_session, data)
    process_pending(db_session)
    detail = auth_client.get('/api/vm/trends/signal-pub-1').json()
    response = auth_client.patch('/api/vm/trends/signal-pub-1/review', json={
        'version': detail['version'], 'publication_key': 'pub-1', 'revision': 1,
        'linked_identifier': 'CVE-2026-99999', 'independent': True, 'note': 'Vendor assigned identifier'})
    assert response.status_code == 200, response.text
    apply_page(db_session, {**data, 'epoch': 'restored'}, reset=True)
    process_pending(db_session)
    linked = auth_client.get('/api/vm/trends/CVE-2026-99999').json()
    assert linked['evidence_total'] == 1
    assert linked['evidence'][0]['independent'] is True


def test_restore_reused_revision_never_reuses_confirmation_for_different_text(auth_client, db_session):
    data = page()
    data['events'][1]['payload'].update(published_at=dt.datetime.now(dt.UTC).isoformat(), exploitation_confirmed=False)
    apply_page(db_session, data)
    process_pending(db_session)
    detail = auth_client.get('/api/vm/trends/CVE-2026-12345').json()
    auth_client.patch('/api/vm/trends/CVE-2026-12345/review', json={'version': detail['version'],
        'publication_key': 'pub-1', 'revision': 1, 'confirm_exploitation': True})
    data['events'][1]['payload']['text'] = 'Vendor retracts earlier exploitation statement'
    apply_page(db_session, {**data, 'epoch': 'restored'}, reset=True)
    process_pending(db_session)
    changed = auth_client.get('/api/vm/trends/CVE-2026-12345').json()
    assert changed['evidence'][0]['exploitation_verified'] is False
    assert changed['active'] is False


def test_trends_permissions(client_as):
    auditor = client_as('auditor')
    assert auditor.get('/api/vm/trends').status_code == 200
    assert auditor.post('/api/vm/trends/sync').status_code == 403
    analyst = client_as('analyst')
    assert analyst.put('/api/vm/trends/settings', json={}).status_code == 403
    for path in ('sources', 'sync/full', 'import/full'):
        assert analyst.post('/api/vm/trends/' + path).status_code == 403


def test_ghsa_image_matching_ignores_identifier_case(auth_client, db_session):
    from api.modules.vm.models import VmImage, VmImageCve
    data = page()
    data['events'][1]['payload'].update(title='GHSA-abcd-efgh-2345', text='GHSA-abcd-efgh-2345',
        identifiers=['GHSA-abcd-efgh-2345'], published_at=dt.datetime.now(dt.UTC).isoformat())
    apply_page(db_session, data)
    process_pending(db_session)
    image = VmImage(project='test', repository='app', digest='sha256:abc')
    db_session.add(image)
    db_session.flush()
    db_session.add(VmImageCve(image_id=image.id, cve_id='GHSA-abcd-efgh-2345', package='package', installed_version='1', trivy_severity='high'))
    db_session.commit()
    result = auth_client.get('/api/vm/trends').json()
    assert result['total'] == 1 and result['items'][0]['images'] == 1
    detail = auth_client.get('/api/vm/trends/GHSA-ABCD-EFGH-2345').json()
    assert detail['matches']['image_finding_total'] == 1
    assert auth_client.get('/api/vm/trends/badges?ids=GHSA-abcd-efgh-2345').json()['GHSA-abcd-efgh-2345']


def news_page(publications):
    data = page()
    events = []
    for index, overrides in enumerate(publications):
        publisher = overrides.get('publisher_id', f'publisher-{index}')
        source_id = f'source-{index}'
        events.append({**data['events'][0], 'seq': len(events)+1, 'entity_id': source_id,
                       'payload': {'id': source_id, 'name': publisher, 'publisher_id': publisher, 'adapter': 'rss'}})
        payload = {**data['events'][1]['payload'], 'source_id': source_id, 'publisher_id': publisher,
                   'url': f'https://{publisher}.test/article-{index}', 'evidence_kind': 'news',
                   'exploitation_confirmed': False, 'published_at': dt.datetime.now(dt.UTC).isoformat(),
                   'text': f'Independent reporting with details from {publisher}', **overrides}
        events.append({**data['events'][1], 'seq': len(events)+1, 'entity_id': f'pub-{index}', 'payload': payload})
    return {**data, 'events': events, 'until_seq': len(events), 'next_cursor': len(events)}


def test_automatic_news_qualification_counts_and_manual_override(auth_client, db_session):
    data = news_page([{'links': ['https://nvd.nist.gov/vuln/detail/CVE-2026-12345']},
                      {'links': ['https://nvd.nist.gov/vuln/detail/CVE-2026-12345'], 'title': 'Latest relevant news'}])
    apply_page(db_session, data)
    process_pending(db_session)
    result = auth_client.get('/api/vm/trends?view=all').json()
    assert result['total'] == 1
    card = result['items'][0]
    assert card['publication_count'] == card['publisher_count'] == card['independent_sources'] == card['news_count'] == 2
    assert card['title'] == 'Latest relevant news'
    assert card['source_name'] == 'publisher-1'
    assert card['source_url'] == 'https://publisher-1.test/article-1'
    detail = auth_client.get('/api/vm/trends/CVE-2026-12345').json()
    assert detail['publication_count'] == detail['evidence_total'] == 2
    assert detail['evidence'][0]['title'] == 'Latest relevant news'
    assert detail['source_name'] == detail['evidence'][0]['source_name']
    assert detail['source_url'] == detail['evidence'][0]['url']
    response = auth_client.patch('/api/vm/trends/CVE-2026-12345/review', json={
        'version': detail['version'], 'publication_key': 'pub-1', 'revision': 1, 'independent': False})
    assert response.status_code == 200, response.text
    assert response.json()['independent_sources'] == 1
    assert auth_client.get('/api/vm/trends?view=all').json()['total'] == 0
    assert auth_client.get('/api/vm/trends?view=mentions').json()['total'] == 1


def test_period_filters_old_catalog_but_keeps_new_reports_about_old_cve(auth_client, db_session):
    old = {'title': 'Old catalog CVE-2011-3402', 'identifiers': ['CVE-2011-3402'],
           'published_at': '2025-10-06T00:00:00Z', 'evidence_kind': 'kev', 'exploitation_confirmed': True}
    recent = {'title': 'New attack on CVE-2011-3402', 'identifiers': ['CVE-2011-3402']}
    data = news_page([old, recent, recent])
    data['events'][0]['payload']['adapter'] = 'kev'
    apply_page(db_session, data)
    process_pending(db_session)
    current = auth_client.get('/api/vm/trends?view=all').json()
    assert current['total'] == 1
    assert current['items'][0]['publication_count'] == 2
    assert current['items'][0]['title'] == recent['title']
    history = auth_client.get('/api/vm/trends/CVE-2011-3402?period=all').json()
    assert history['evidence_total'] == 3
    historical = auth_client.get('/api/vm/trends?view=all&period=custom&date_from=2025-10-06&date_to=2025-10-06&tz=UTC').json()
    assert historical['total'] == 1
    assert historical['items'][0]['publication_count'] == 1
    assert historical['items'][0]['source_url'] == 'https://publisher-0.test/article-0'
    assert historical['items'][0]['reason'] == 'confirmed_exploitation'


def test_mentions_and_review_require_recent_valid_evidence(auth_client, db_session):
    data = news_page([{}, {'identifiers': ['CVE-2011-3402'], 'title': 'Old catalog', 'published_at': '2025-10-06T00:00:00Z'},
                      {'identifiers': [], 'title': 'Early product signal'},
                      {'identifiers': ['CVE-2026-99999'], 'published_at': None},
                      {'identifiers': ['CVE-2026-88888'], 'published_at': (dt.datetime.now(dt.UTC)+dt.timedelta(days=1)).isoformat()}])
    apply_page(db_session, data)
    process_pending(db_session)
    assert auth_client.get('/api/vm/trends?view=all').json()['total'] == 0
    mentions = auth_client.get('/api/vm/trends?view=mentions').json()
    assert [row['id'] for row in mentions['items']] == ['CVE-2026-12345']
    review = auth_client.get('/api/vm/trends?view=review').json()
    assert {row['id'] for row in review['items']} == {'CVE-2026-12345', 'signal-pub-2'}
    assert auth_client.get('/api/vm/trends/CVE-2011-3402').json()['evidence_total'] == 0


def test_period_inputs_are_validated(auth_client):
    for suffix in ('period=custom', 'period=custom&date_from=2026-11-06&date_to=2026-11-05',
                   'period=custom&date_from=no&date_to=2026-11-05', 'tz=Unknown/Timezone', 'period=wrong'):
        assert auth_client.get('/api/vm/trends?' + suffix).status_code == 422
        assert auth_client.get('/api/vm/trends/CVE-2026-12345?' + suffix).status_code == 422


def test_manual_independence_survives_note_only_review(auth_client, db_session):
    apply_page(db_session, news_page([{}, {}]))
    process_pending(db_session)
    card = auth_client.get('/api/vm/trends/CVE-2026-12345').json()
    first = auth_client.patch('/api/vm/trends/CVE-2026-12345/review', json={
        'version': card['version'], 'publication_key': 'pub-1', 'revision': 1, 'independent': False}).json()
    second = auth_client.patch('/api/vm/trends/CVE-2026-12345/review', json={
        'version': first['version'], 'publication_key': 'pub-1', 'revision': 1, 'note': 'Analyst follow-up'}).json()
    assert second['independent_sources'] == 1
    assert second['active'] is False


def test_api_today_timezone_and_thirty_days_scope_details_and_badges(auth_client, db_session, monkeypatch):
    from api.modules.vm.services.trends import query
    real_datetime = dt.datetime
    now = real_datetime(2026, 11, 5, 12, tzinfo=dt.UTC)
    class FrozenDateTime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return now if tz else now.replace(tzinfo=None)
    data = news_page([{'published_at': '2026-11-04T21:30:00Z'}, {'published_at': '2026-11-04T21:45:00Z'},
                      {'published_at': '2026-10-16T12:00:00Z', 'identifiers': ['CVE-2026-99999']},
                      {'published_at': '2026-10-16T13:00:00Z', 'identifiers': ['CVE-2026-99999']}])
    apply_page(db_session, data)
    process_pending(db_session)
    monkeypatch.setattr(query.dt, 'datetime', FrozenDateTime)
    assert auth_client.get('/api/vm/trends?view=all&period=today&tz=Europe/Moscow').json()['total'] == 1
    assert auth_client.get('/api/vm/trends?view=all&period=today&tz=UTC').json()['total'] == 0
    assert auth_client.get('/api/vm/trends?view=all&period=30d').json()['total'] == 2
    detail = auth_client.get('/api/vm/trends/CVE-2026-99999?period=30d').json()
    assert detail['active'] and detail['evidence_total'] == detail['publication_count'] == 2
    assert auth_client.get('/api/vm/trends/badges?ids=CVE-2026-99999').json() == {}


def test_review_excludes_already_qualified_trends(auth_client, db_session):
    apply_page(db_session, news_page([{}, {}]))
    process_pending(db_session)
    assert auth_client.get('/api/vm/trends?view=all').json()['total'] == 1
    assert auth_client.get('/api/vm/trends?view=review').json()['total'] == 0


def test_rejected_evidence_remains_visible_for_restore_but_does_not_count(auth_client, db_session):
    apply_page(db_session, news_page([{}]))
    process_pending(db_session)
    card = auth_client.get('/api/vm/trends/CVE-2026-12345').json()
    rejected = auth_client.patch('/api/vm/trends/CVE-2026-12345/review', json={
        'version': card['version'], 'publication_key': 'pub-0', 'revision': 1, 'rejected': True})
    assert rejected.status_code == 200
    detail = auth_client.get('/api/vm/trends/CVE-2026-12345').json()
    assert detail['publication_count'] == detail['publisher_count'] == detail['independent_sources'] == 0
    assert len(detail['evidence']) == 1
    assert detail['evidence'][0]['rejected'] is True
    assert auth_client.get('/api/vm/trends?view=mentions').json()['total'] == 0
    restored = auth_client.patch('/api/vm/trends/CVE-2026-12345/review', json={
        'version': detail['version'], 'publication_key': detail['evidence'][0]['publication_key'], 'revision': 1, 'rejected': False})
    assert restored.status_code == 200
    assert restored.json()['publication_count'] == 1
    assert restored.json()['evidence'][0]['rejected'] is False
    assert auth_client.get('/api/vm/trends?view=mentions').json()['total'] == 1


def test_retracted_evidence_is_auditable_only_in_its_selected_period(auth_client, db_session):
    from sqlalchemy import select

    from api.modules.vm.trend_models import VmTrendPublication
    apply_page(db_session, news_page([{}, {'published_at': '2025-10-06T00:00:00Z'}]))
    process_pending(db_session)
    for publication in db_session.scalars(select(VmTrendPublication)):
        publication.retracted = True
    db_session.commit()
    current = auth_client.get('/api/vm/trends/CVE-2026-12345').json()
    assert current['publication_count'] == 0 and current['active'] is False
    assert len(current['evidence']) == 1 and current['evidence'][0]['retracted'] is True
    history = auth_client.get('/api/vm/trends/CVE-2026-12345?period=all').json()
    assert history['publication_count'] == 0 and len(history['evidence']) == 2
    assert auth_client.get('/api/vm/trends?view=mentions&period=all').json()['total'] == 0
    assert auth_client.get('/api/vm/trends/badges?ids=CVE-2026-12345').json() == {}


def test_diagnostic_archive_preserves_background_and_unknown_dates(auth_client, db_session):
    classification={'category':'background','reasons':['Не относится к уязвимостям'],'identifier_roles':[],'rule_version':1}
    apply_page(db_session,news_page([{'title':'AI detects diseases','identifiers':[],'text':'Medical research','classification':classification},
        {'title':'Undated security report','published_at':None}]))
    process_pending(db_session)
    assert auth_client.get('/api/vm/trends?view=review').json()['total']==0
    result=auth_client.get('/api/vm/trends?view=archive&period=all').json()
    assert result['total']==2
    undated=next(row for row in result['items'] if row['title']=='Undated security report')
    detail=auth_client.get('/api/vm/trends/'+undated['id']+'?period=all').json()
    assert detail['evidence_total']==1 and detail['evidence'][0]['published_at'] is None


def test_source_filter_limits_loaded_cards_but_keeps_other_publishers(auth_client, db_session, monkeypatch):
    from api.modules.vm.services.trends import query
    data = news_page([
        {'identifiers': ['CVE-2026-12345']},
        {'identifiers': ['CVE-2026-12345']},
        {'identifiers': ['CVE-2026-23456'], 'title': 'Unrelated CVE-2026-23456'},
    ])
    apply_page(db_session, data)
    process_pending(db_session)
    original = query.evidence_for
    loaded = []
    def capture(db, card_ids, *args, **kwargs):
        loaded.extend(card_ids)
        return original(db, card_ids, *args, **kwargs)
    monkeypatch.setattr(query, 'evidence_for', capture)
    response = auth_client.get('/api/vm/trends?view=all&period=30d&source_id=source-0')
    assert response.status_code == 200
    assert loaded == ['CVE-2026-12345']
    assert response.json()['items'][0]['publisher_count'] == 2


def test_monthly_results_and_refresh_use_bounded_evidence_batches(auth_client, db_session, monkeypatch):
    from api.modules.vm.services.trends import analyze, query
    rows=[{'identifiers':[f'CVE-2026-{20000+i}'], 'title':f'Security issue CVE-2026-{20000+i}'} for i in range(125)]
    apply_page(db_session,news_page(rows))
    sizes=[]; original=analyze.evidence_for
    def capture(db,card_ids,*args,**kwargs):
        sizes.append(len(card_ids))
        return original(db,card_ids,*args,**kwargs)
    monkeypatch.setattr(analyze,'evidence_for',capture)
    process_pending(db_session)
    assert sizes and max(sizes)<len(rows)
    sizes.clear();monkeypatch.setattr(query,'evidence_for',capture)
    response=auth_client.get('/api/vm/trends?view=mentions&period=30d&limit=10&offset=100')
    assert response.status_code==200
    assert response.json()['total']==125 and len(response.json()['items'])==10
    assert sizes and max(sizes)<len(rows)
