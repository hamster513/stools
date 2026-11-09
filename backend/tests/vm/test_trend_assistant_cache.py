import json
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.vm.services.trends import assistant
from api.modules.vm.trend_models import VmTrendPublication, VmTrendEnrichment
from tests.vm.test_trend_assistant import prepared, URL, TRANSLATION, EXPLANATION  # noqa: F401


@pytest.mark.parametrize('target', ['card', 'article'])
def test_answers_survive_reopening_and_switching_modes_without_new_calls(auth_client, prepared, target):
    calls, article = prepared
    params = article if target == 'article' else {}
    answers = {mode: auth_client.post(URL, json={'mode': mode, **params}).json() for mode in ('translate', 'explain')}
    reopened = auth_client.get(URL, params=params)
    assert reopened.status_code == 200, reopened.text
    for mode, answer in answers.items():
        assert reopened.json()[mode]['generated_at'] == answer['generated_at']
        assert reopened.json()[mode]['stale'] is False
        assert auth_client.post(URL, json={'mode': mode, **params}).json()['generated_at'] == answer['generated_at']
    assert len(calls) == 2


def test_cached_answer_does_not_depend_on_current_provider(auth_client, prepared):
    calls, _ = prepared
    first = auth_client.post(URL, json={'mode': 'translate'}).json()
    auth_client.put('/api/settings/llm', json={'enabled': False, 'tasks': {
        'vulnerability_assistant': {'provider': 'ollama', 'model': 'different-model'}}})
    repeated = auth_client.post(URL, json={'mode': 'translate'})
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()['generated_at'] == first['generated_at']
    assert len(calls) == 1


def test_updated_text_keeps_previous_answer_until_manual_update(auth_client, db_session, prepared):
    calls, article = prepared
    first = auth_client.post(URL, json={'mode': 'translate', **article}).json()
    row = db_session.scalar(select(VmTrendPublication).limit(1))
    row.data = {**row.data, 'text': 'The text has changed'}
    row.revision += 1
    db_session.commit()
    params = {**article, 'revision': row.revision}
    previous = auth_client.get(URL, params=params).json()['translate']
    assert previous['stale'] is True
    assert previous['generated_at'] == first['generated_at']
    assert len(calls) == 1
    updated = auth_client.post(URL, json={'mode': 'translate', **params})
    assert updated.status_code == 200, updated.text
    assert auth_client.get(URL, params=params).json()['translate']['stale'] is False
    assert len(calls) == 2


def test_refresh_timestamps_and_model_dont_spend_tokens_again(auth_client, db_session, prepared):
    calls, _ = prepared
    pub = db_session.scalar(select(VmTrendPublication).limit(1))
    row = VmTrendEnrichment(generation=pub.generation, external_id='cve:CVE-2026-12345', revision=1,
        data={'description': 'A description', 'epss': 0.003, 'fetched_at': '2026-11-07T10:00:00Z'})
    db_session.add(row);db_session.commit()
    auth_client.post(URL, json={'mode': 'translate'})
    row.data = {**row.data, 'fetched_at': '2026-11-07T11:00:00Z', 'epss': 0.004}
    row.revision += 1;db_session.commit()
    assert auth_client.get(URL).json()['translate']['stale'] is False
    assert auth_client.post(URL, json={'mode': 'translate'}).status_code == 200
    assert len(calls) == 1


def test_parallel_requests_call_provider_once(auth_client, db_session, prepared, monkeypatch):
    entered, release, second_started = Event(), Event(), Event()
    calls, mutex = [], Lock()
    class Slow:
        def __init__(self, config): pass
        def complete(self, prompt, schema):
            with mutex: calls.append(prompt)
            entered.set()
            assert release.wait(10)
            return json.dumps(TRANSLATION)
    monkeypatch.setattr(assistant, 'OllamaCompletion', Slow)
    engine = db_session.get_bind()
    def work(second=False):
        if second: second_started.set()
        with Session(engine, expire_on_commit=False) as db:
            return assistant.respond(db, 'CVE-2026-12345', assistant.AssistantRequest(mode='translate'))
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(work)
        try:
            assert entered.wait(10)
            second = executor.submit(work, True)
            assert second_started.wait(10)
        finally:
            release.set()
        a, b = first.result(15), second.result(15)
    assert a['generated_at'] == b['generated_at']
    assert len(calls) == 1


def test_auditor_can_read_saved_answer_but_cannot_generate(auth_client, client_as, prepared):
    auth_client.post(URL, json={'mode': 'translate'})
    auditor = client_as('auditor')
    assert auditor.get(URL).json()['translate']['translation']
    assert auditor.post(URL, json={'mode': 'translate'}).status_code == 403


@pytest.mark.parametrize('changed_text', [False, True])
def test_paid_answer_survives_refresh_during_generation(auth_client, db_session, prepared, monkeypatch, changed_text):
    publication = db_session.scalar(select(VmTrendPublication).limit(1))
    enrichment = VmTrendEnrichment(generation=publication.generation, external_id='cve:CVE-2026-12345', revision=1,
        data={'description': 'Original description', 'epss': 0.003, 'fetched_at': '2026-11-07T10:00:00Z'})
    db_session.add(enrichment);db_session.commit()
    class Refreshing:
        def __init__(self, config): pass
        def complete(self, *args):
            enrichment.data = {**enrichment.data, 'fetched_at': '2026-11-07T11:00:00Z', 'epss': 0.004,
                'description': 'New description' if changed_text else 'Original description'}
            enrichment.revision += 1;db_session.commit()
            return json.dumps(TRANSLATION)
    monkeypatch.setattr(assistant, 'OllamaCompletion', Refreshing)
    response = auth_client.post(URL, json={'mode': 'translate'})
    assert response.status_code == 200, response.text
    assert response.json()['stale'] is changed_text
    saved = auth_client.get(URL).json()['translate']
    assert saved['translation'] == TRANSLATION['translation']
    assert saved['stale'] is changed_text
