import json

import pytest
from sqlalchemy import select

from api.modules.vm.services.trends import assistant
from api.modules.vm.services.trends.analyze import process_pending
from api.modules.vm.services.trends.ingest import apply_page
from api.modules.vm.trend_models import VmTrendPublication, VmTrendSource
from tests.vm.test_trend_sync import page

URL = '/api/vm/trends/CVE-2026-12345/assistant'
TRANSLATION = {'translation': 'Подтверждённая эксплуатация'}
EXPLANATION = {'summary': 'CVE-2026-12345: ошибка в продукте', 'danger': 'Возможен доступ к данным',
               'affected': 'Версии не указаны', 'actions': ['Проверить бюллетень'], 'limitations': ['Мало данных']}


@pytest.fixture
def prepared(auth_client, db_session, monkeypatch):
    payload = page()
    payload['events'][0]['payload']['llm_allowed'] = True
    apply_page(db_session, payload)
    process_pending(db_session)
    settings = {'base_url': 'http://local:11434', 'tasks': {
        'threat_analysis': {'provider': 'ollama', 'model': 'background-model'},
        'vulnerability_assistant': {'provider': 'ollama', 'model': 'explainer'}}}
    assert auth_client.put('/api/settings/llm', json=settings).status_code == 204
    calls = []
    class Completion:
        def __init__(self, config): self.config = config
        def complete(self, prompt, schema):
            calls.append((self.config.model, prompt))
            return json.dumps(TRANSLATION if 'translation' in schema['properties'] else EXPLANATION)
    monkeypatch.setattr(assistant, 'OllamaCompletion', Completion)
    detail = auth_client.get('/api/vm/trends/CVE-2026-12345?period=all').json()
    article = detail['evidence'][0]
    return calls, {'publication_key': article['publication_key'], 'revision': article['revision']}


@pytest.mark.parametrize('mode', ['translate', 'explain'])
@pytest.mark.parametrize('target', ['card', 'article'])
def test_assistant_uses_dedicated_model_and_stored_public_text(auth_client, db_session, prepared, mode, target):
    calls, article = prepared
    result = auth_client.post(URL, json={'mode': mode, **(article if target == 'article' else {})})
    assert result.status_code == 200, result.text
    body = result.json()
    assert body['model'] == 'explainer' and body['mode'] == mode
    assert body['sources'][0]['url'] == 'https://example.test/a'
    assert ('translation' in body) == (mode == 'translate')
    assert calls[0][0] == 'explainer'
    assert 'Confirmed exploitation' in calls[0][1]
    assert not any(key in calls[0][1] for key in ('local_ref', 'hostname', '192.0.2.', 'host_id'))
    row = db_session.scalar(select(VmTrendPublication).limit(1))
    assert 'translation' not in row.analysis


@pytest.mark.parametrize('changes,status', [({'revision': 999}, 409), ({'publication_key': 'unrelated'}, 404)])
def test_article_revision_and_card_membership_checked_before_llm(auth_client, prepared, changes, status):
    calls, article = prepared
    r = auth_client.post(URL, json={'mode': 'explain', **article, **changes})
    assert r.status_code == status
    assert calls == []


def test_manual_request_does_not_require_or_enable_background_analysis(auth_client, db_session, prepared):
    calls, article = prepared
    source = db_session.scalar(select(VmTrendSource).limit(1))
    source.data = {**source.data, 'llm_allowed': False}
    db_session.commit()
    assert auth_client.post(URL, json={'mode': 'explain', **article}).status_code == 200
    db_session.refresh(source)
    assert source.data['llm_allowed'] is False
    assert len(calls) == 1


def test_internal_source_never_reaches_external_provider(auth_client, db_session, prepared):
    calls, article = prepared
    source = db_session.scalar(select(VmTrendSource).limit(1))
    source.data = {**source.data, 'data_class': 'internal'}
    db_session.commit()
    auth_client.put('/api/settings/llm', json={'tasks': {'vulnerability_assistant': {
        'provider': 'deepseek', 'model': 'remote'}}, 'key_updates': {'deepseek': 'test-key'}})
    assert auth_client.post(URL, json={'mode': 'explain', **article}).status_code == 409
    assert calls == []


def test_disabled_task_and_invalid_request_do_not_call_model(auth_client, prepared):
    calls, article = prepared
    auth_client.put('/api/settings/llm', json={'tasks': {'vulnerability_assistant': {
        'provider': 'ollama', 'model': 'explainer', 'enabled': False}}})
    assert auth_client.post(URL, json={'mode': 'explain', **article}).status_code == 409
    assert auth_client.post(URL, json={'mode': 'execute'}).status_code == 422
    assert auth_client.post(URL, json={'mode': 'explain', 'text': 'arbitrary text'}).status_code == 422
    assert calls == []


def test_provider_failure_does_not_leak_details(auth_client, prepared, monkeypatch):
    from kbaudit.attack.provider import ModelError
    class Broken:
        def __init__(self, config): pass
        def complete(self, *args): raise ModelError('secret-key private-provider-url')
    monkeypatch.setattr(assistant, 'OllamaCompletion', Broken)
    result = auth_client.post(URL, json={'mode': 'explain'})
    assert result.status_code == 502
    assert 'secret-key' not in result.text and 'private-provider-url' not in result.text


def test_invalid_model_json_is_reported(auth_client, prepared, monkeypatch):
    class Broken:
        def __init__(self, config): pass
        def complete(self, *args): return '{"summary":"missing required fields"}'
    monkeypatch.setattr(assistant, 'OllamaCompletion', Broken)
    assert auth_client.post(URL, json={'mode': 'explain'}).status_code == 502


def test_assistant_requires_analyst(client_as):
    assert client_as('auditor').post(URL, json={'mode': 'explain'}).status_code == 403


def test_changed_publication_during_generation_is_not_returned(auth_client, db_session, prepared, monkeypatch):
    calls, article = prepared
    class Changed:
        def __init__(self, config): pass
        def complete(self, *args):
            row = db_session.scalar(select(VmTrendPublication).limit(1))
            row.revision += 1
            db_session.commit()
            return json.dumps(EXPLANATION)
    monkeypatch.setattr(assistant, 'OllamaCompletion', Changed)
    result = auth_client.post(URL, json={'mode': 'explain', **article})
    assert result.status_code == 409
    assert 'summary' not in result.json()


def test_news_without_cve_can_be_explained(auth_client, db_session, prepared):
    calls, _ = prepared
    payload = page()
    payload['events'][1]['payload'].update(identifiers=[], title='Security news without CVE')
    payload['events'][1]['revision'] = 2
    payload['events'][1]['seq'] = 3
    payload.update(until_seq=3, next_cursor=3, events=[payload['events'][1]])
    apply_page(db_session, payload)
    process_pending(db_session)
    result = auth_client.post('/api/vm/trends/signal-pub-1/assistant', json={'mode': 'explain'})
    assert result.status_code == 200, result.text
    assert 'Security news without CVE' in calls[-1][1]


@pytest.mark.parametrize('exclusion', ['rejected', 'suppressed'])
def test_card_excludes_rejected_material_but_direct_explanation_keeps_status(auth_client, prepared, exclusion):
    calls, article = prepared
    if exclusion == 'rejected':
        r = auth_client.patch('/api/vm/trends/CVE-2026-12345/review', json={
            'version': 1, **article, 'rejected': True, 'note': 'False positive'})
    else:
        r = auth_client.post('/api/vm/trends/policies', json={
            'scope': 'publication', 'target_key': article['publication_key'], 'reason': 'False positive'})
    assert r.status_code == 200, r.text
    result = auth_client.post(URL, json={'mode': 'explain'})
    assert result.status_code == 409
    assert not calls
    result = auth_client.post(URL, json={'mode': 'explain', **article})
    assert result.status_code == 200, result.text
    assert exclusion in calls[0][1]
    assert 'False positive' not in calls[0][1]  # Internal analyst comments stay local.


def test_card_finds_allowed_article_after_excluded_batch(auth_client, db_session, prepared):
    from api.modules.vm.trend_models import VmTrendEvidence
    calls, _ = prepared
    original = db_session.scalar(select(VmTrendPublication).limit(1))
    for index in range(12):
        row = VmTrendPublication(generation=original.generation, external_id=f'background-{index}',
            source_id=original.source_id, revision=1, processing='done', data={**original.data,
                'title': f'Background story {index}', 'published_at': '2026-11-07T10:00:00Z',
                'classification': {'category': 'background'}})
        db_session.add(row)
        db_session.flush()
        db_session.add(VmTrendEvidence(card_id='CVE-2026-12345', publication_id=row.id))
    db_session.commit()
    result = auth_client.post(URL, json={'mode': 'explain'})
    assert result.status_code == 200, result.text
    assert len(result.json()['sources']) == 1
    assert 'Background story' not in calls[0][1]


def test_public_telegram_manual_request_is_independent_of_background(auth_client, db_session, prepared):
    calls, article = prepared
    source = db_session.scalar(select(VmTrendSource).limit(1))
    source.data = {**source.data, 'adapter': 'telegram', 'llm_allowed': False}
    db_session.commit()
    assert auth_client.post(URL, json={'mode': 'explain', **article}).status_code == 200
    assert auth_client.post(URL, json={'mode': 'explain'}).status_code == 200
    db_session.refresh(source)
    assert source.data['llm_allowed'] is False
    assert len(calls) == 2


@pytest.mark.parametrize('mode', ['translate', 'explain'])
def test_cve_help_uses_description_without_mixing_other_news(auth_client, db_session, prepared, mode):
    from api.modules.vm.trend_models import VmTrendEnrichment
    calls, _ = prepared
    publication = db_session.scalar(select(VmTrendPublication).limit(1))
    db_session.add(VmTrendEnrichment(generation=publication.generation, external_id='cve:CVE-2026-12345',
        revision=1, data={'description': 'The affected product exposes private data', 'cvss': 5.5, 'epss': 0.003}))
    db_session.commit()
    r = auth_client.post(URL, json={'mode': mode})
    assert r.status_code == 200, r.text
    assert 'The affected product exposes private data' in calls[0][1]
    assert 'Confirmed exploitation' not in calls[0][1]
    assert len(r.json()['sources']) == 1


@pytest.mark.parametrize('target,status', [('card', 502), ('article', 200)])
def test_explanation_cannot_substitute_another_cve(auth_client, prepared, monkeypatch, target, status):
    _, article = prepared
    class WrongCve:
        def __init__(self, config): pass
        def complete(self, *args): return json.dumps({**EXPLANATION, 'summary': 'CVE-2026-99999 is a different vulnerability'})
    monkeypatch.setattr(assistant, 'OllamaCompletion', WrongCve)
    result = auth_client.post(URL, json={'mode': 'explain', **(article if target == 'article' else {})})
    assert result.status_code == status


def test_explanation_preserves_cross_reference_from_cve_description(auth_client, db_session, prepared, monkeypatch):
    from api.modules.vm.trend_models import VmTrendEnrichment
    publication = db_session.scalar(select(VmTrendPublication).limit(1))
    db_session.add(VmTrendEnrichment(generation=publication.generation, external_id='cve:CVE-2026-12345', revision=1,
        data={'description': 'CVE-2026-12345 is an incomplete fix for CVE-2026-22222'}))
    db_session.commit()
    class Related:
        def __init__(self, config): pass
        def complete(self, *args): return json.dumps({**EXPLANATION, 'summary': 'CVE-2026-12345: неполное исправление CVE-2026-22222'})
    monkeypatch.setattr(assistant, 'OllamaCompletion', Related)
    result = auth_client.post(URL, json={'mode': 'explain'})
    assert result.status_code == 200, result.text
