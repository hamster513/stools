import json

import pytest

from api.llm_settings import load_llm
from kbaudit.attack.provider import ModelError

URL = '/api/settings/llm'
TASKS = {'attack_embeddings', 'attack_markup', 'attack_translation', 'threat_analysis', 'vulnerability_assistant'}


def assignment(provider='ollama', model='local-model', **kw):
    return dict(provider=provider, model=model, enabled=True, timeout=60, think=False, local_only=False, **kw)


def test_legacy_materializes_equivalent_tasks_without_writing(auth_client, db_session):
    from api.db.models import AppSetting
    payload = {'provider': 'deepseek', 'api_key': 'ds-key', 'base_url': 'http://local:11434',
               'model': 'remote-model', 'embed_model': 'local-embed', 'think': True, 'timeout': 75}
    assert auth_client.put(URL, json=payload).status_code == 204
    before = db_session.get(AppSetting, 'llm').value_json
    body = auth_client.get(URL).json()
    assert set(body['tasks']) == TASKS
    assert body['tasks']['attack_markup']['provider'] == 'deepseek'
    assert body['tasks']['attack_translation']['model'] == 'remote-model'
    assert body['tasks']['threat_analysis']['think'] is True
    assert body['tasks']['attack_embeddings']['provider'] == 'ollama'
    assert body['tasks']['attack_embeddings']['model'] == 'local-embed'
    assert db_session.get(AppSetting, 'llm').value_json == before


def test_independent_tasks_resolve_their_own_keys(auth_client, db_session):
    tasks = {'attack_embeddings': assignment(model='vectors'),
             'attack_markup': assignment('deepseek', 'reasoning-model'),
             'attack_translation': assignment('openrouter', 'translator'),
             'threat_analysis': assignment(model='local-analysis'),
             'vulnerability_assistant': assignment(model='local-explainer')}
    assert auth_client.put(URL, json={'base_url': 'http://local:11434', 'tasks': tasks,
        'key_updates': {'openrouter': 'router-key', 'deepseek': 'ds-key'}}).status_code == 204
    db_session.expire_all()
    settings = load_llm(db_session)
    assert settings.for_task('attack_markup', data_class='redacted').api_key.get_secret_value() == 'ds-key'
    assert settings.for_task('attack_translation', data_class='public').api_key.get_secret_value() == 'router-key'
    local = settings.for_task('threat_analysis', data_class='internal')
    assert local.provider == 'ollama' and not local.api_key.get_secret_value()
    assert local.model == 'local-analysis'
    response = auth_client.get(URL)
    assert 'router-key' not in response.text and 'ds-key' not in response.text and 'key_updates' not in response.json()
    assert response.json()['tasks'] == tasks
    assert auth_client.put(URL, json={**response.json(), 'key_updates': {'deepseek': ''}}).status_code == 204
    db_session.expire_all()
    settings = load_llm(db_session)
    assert not settings.task_configured('attack_markup')
    assert settings.task_configured('attack_translation')


def test_internal_data_and_unclassified_data_cannot_use_external_models(auth_client, db_session):
    auth_client.put(URL, json={'tasks': {'threat_analysis': assignment('deepseek', 'external')},
                             'key_updates': {'deepseek': 'ds-key'}})
    db_session.expire_all()
    settings = load_llm(db_session)
    with pytest.raises(ModelError, match='(?i)внутренн'):
        settings.for_task('threat_analysis', data_class='internal')
    with pytest.raises(ModelError, match='(?i)внутренн'):
        settings.for_task('threat_analysis')
    assert settings.for_task('threat_analysis', data_class='public').model == 'external'


@pytest.mark.parametrize('tasks', [
    {'attack_embeddings': assignment('deepseek', 'not-an-embedder')},
    {'threat_analysis': {**assignment('deepseek', 'external'), 'local_only': True}},
    {'unknown_task': assignment()},
])
def test_invalid_assignments_are_rejected_before_save(auth_client, tasks):
    before = auth_client.get(URL).json()
    assert auth_client.put(URL, json={'tasks': tasks}).status_code == 422
    assert auth_client.get(URL).json() == before


def test_disable_and_readiness_are_per_task(auth_client, db_session):
    tasks = {'attack_translation': {**assignment(), 'enabled': False},
             'attack_markup': assignment(), 'attack_embeddings': assignment(model='vectors')}
    auth_client.put(URL, json={'base_url': 'http://local:11434', 'tasks': tasks})
    db_session.expire_all()
    settings = load_llm(db_session)
    assert settings.task_configured('attack_markup')
    assert not settings.task_configured('attack_translation')
    with pytest.raises(ModelError):
        settings.for_task('attack_translation', data_class='public')
    tasks['attack_embeddings']['model'] = ''
    auth_client.put(URL, json={'base_url': 'http://local:11434', 'tasks': tasks})
    db_session.expire_all()
    assert not load_llm(db_session).task_configured('attack_embeddings')
    assert auth_client.post('/api/settings/attack/translate').status_code == 409


def test_task_test_uses_embeddings_and_unsaved_assignment(auth_client, monkeypatch):
    from api.platform.routers import llm
    seen = []
    def embed(self, texts):
        seen.append(self._settings)
        return [[1, 2]]
    monkeypatch.setattr(llm.OllamaEmbedder, 'embed', embed, raising=False)
    result = auth_client.post(URL + '/test', json={'task': 'attack_embeddings',
        'assignment': assignment('openrouter', 'embed-model'), 'api_key': 'unsaved-key'})
    assert result.status_code == 200 and result.json()['ok']
    assert seen[0].embed_model == 'embed-model'
    assert seen[0].api_key.get_secret_value() == 'unsaved-key'
    assert not auth_client.get(URL).json()['api_keys']['openrouter']


def test_publication_worker_uses_its_task_and_blocks_internal(auth_client, db_session, monkeypatch):
    from api.modules.vm.services.trends import analyze
    from api.modules.vm.services.trends.ingest import apply_page
    from api.modules.vm.trend_models import VmTrendPublication
    from tests.vm.test_trend_sync import page
    data = page()
    data['events'][0]['payload'].update(llm_allowed=True)
    data['events'][1]['payload']['data_class'] = 'internal'
    apply_page(db_session, data)
    auth_client.put(URL, json={'tasks': {'threat_analysis': assignment('deepseek', 'external')},
                             'key_updates': {'deepseek': 'test-key'}})
    calls = []
    class Provider:
        def __init__(self, config): self.config = config
        def complete(self, prompt, schema):
            calls.append(self.config.model)
            return json.dumps({'summary_ru': 'Summary', 'quote': '', 'exploitation_claim': False})
    monkeypatch.setattr(analyze, 'OllamaCompletion', Provider)
    analyze.process_pending(db_session)
    assert not calls
    row = db_session.query(VmTrendPublication).first()
    row.data = {**row.data, 'data_class': 'public'}
    db_session.commit()
    analyze.process_pending(db_session)
    assert calls == ['external']
    assert row.analysis['provider'] == 'deepseek'
    assert row.analysis['model'] == 'external'


def test_partial_save_preserves_other_tasks_and_connections(auth_client):
    tasks = {'attack_translation': assignment('deepseek', 'translator'),
             'threat_analysis': assignment('openrouter', 'analyzer')}
    auth_client.put(URL, json={'base_url': 'http://local:11434', 'tasks': tasks, 'enabled': False,
                             'key_updates': {'deepseek': 'ds-key'}})
    assert auth_client.put(URL, json={'tasks': {'threat_analysis': assignment('openrouter', 'new-analyzer')}}).status_code == 204
    body = auth_client.get(URL).json()
    assert body['tasks']['attack_translation'] == tasks['attack_translation']
    assert body['tasks']['threat_analysis']['model'] == 'new-analyzer'
    assert body['base_url'] == 'http://local:11434' and body['enabled'] is False
    assert auth_client.put(URL, json={'key_updates': {'openrouter': 'or-key'}}).status_code == 204
    after = auth_client.get(URL).json()
    assert after['tasks'] == body['tasks'] and after['base_url'] == body['base_url']


def test_explicit_empty_unsaved_address_does_not_use_saved_server(auth_client, monkeypatch):
    from api.platform.routers import llm
    auth_client.put(URL, json={'base_url': 'http://saved:11434'})
    def no_call(*args): pytest.fail('Used saved address instead of the explicitly cleared input')
    monkeypatch.setattr(llm.OllamaCompletion, 'complete', no_call)
    response = auth_client.post(URL + '/test', json={'task': 'attack_translation', 'assignment': assignment(), 'base_url': ''})
    assert response.status_code == 200 and not response.json()['ok']
