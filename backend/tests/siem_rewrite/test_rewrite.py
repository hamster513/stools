import hashlib
import json

import pytest

from api.db.models import RuleRow
from api.modules.siem.services import rule_rewrite

SOURCE = 'event Login:\n    filter {\n        msgid == "4624"\n    }\nrule Example: Login\non Login {\n    $subject = Login.subject\n}\nemit {\n    $correlation_name = "Example"\n}\n'
CODE = SOURCE.replace('msgid == "4624"', 'msgid == "4624" and subject.name != null')
UUID = 'a' * 32


@pytest.fixture
def rule(db_session, snapshot_id):
    item = RuleRow(snapshot_id=snapshot_id, uuid=UUID, name='Example', body_text=SOURCE,
                   body_hash=hashlib.sha256(SOURCE.encode()).hexdigest(), parse_status='ok')
    db_session.add(item); db_session.commit()
    return item


def url(rule):
    return f'/api/siem/rules/{UUID}/suggestion?snapshot_id={rule.snapshot_id}'


def answer(code=CODE):
    return {'summary': 'Проверка наличия имени пользователя', 'code': code,
            'changes': [{'what': 'Добавлена проверка имени', 'why': 'Исключены события без имени',
                         'impact': 'События без имени больше не подходят'}],
            'dependencies': [], 'tests': [{'event': '4624 с заполненным именем', 'expected': 'Срабатывание'}],
            'limitations': ['Проверить компиляцию в MaxPatrol']}


def fake(auth_client, monkeypatch, result=None):
    assert auth_client.put('/api/settings/llm', json={'base_url': 'http://local:11434', 'tasks': {
        'rule_rewrite': {'provider': 'ollama', 'model': 'coder', 'enabled': True, 'timeout': 60}}}).status_code == 204
    seen = []
    def complete(self, prompt, schema, **kwargs):
        seen.append((prompt, kwargs))
        return json.dumps(result if result is not None else answer())
    monkeypatch.setattr(rule_rewrite.OllamaCompletion, 'complete', complete)
    return seen


def test_full_code_diff_cache_and_original_unchanged(auth_client, db_session, rule, monkeypatch):
    seen = fake(auth_client, monkeypatch)
    before = auth_client.get(url(rule)).json()
    assert before['suggestion'] is None
    response = auth_client.post(url(rule), json={'context_hash': before['context_hash']})
    assert response.status_code == 200, response.text
    data = response.json()['suggestion']
    assert data['code'] == CODE and data['original_code'] == SOURCE
    assert data['changed_lines'] > 0 and any(x['kind'] == 'replace' for x in data['lines'])
    assert data['model'] == 'coder' and data['validated_in_siem'] is False
    assert 'Example' in seen[0][0] and 'недоверенные' in seen[0][0]
    assert seen[0][1]['require_complete'] is True
    assert auth_client.get(url(rule)).json()['suggestion']['code'] == CODE
    db_session.refresh(rule)
    assert rule.body_text == SOURCE


@pytest.mark.parametrize('code', ['', '```\n' + CODE + '```', 'rule Example: Login\n...', CODE.replace('event Login:', 'event Other:')])
def test_fragment_or_malformed_output_rejected(auth_client, rule, monkeypatch, code):
    fake(auth_client, monkeypatch, answer(code))
    ctx = auth_client.get(url(rule)).json()['context_hash']
    assert auth_client.post(url(rule), json={'context_hash': ctx}).status_code == 502
    assert auth_client.get(url(rule)).json()['suggestion'] is None


def test_changed_source_invalidates_result_and_rejects_stale_request(auth_client, db_session, rule, monkeypatch):
    fake(auth_client, monkeypatch)
    context = auth_client.get(url(rule)).json()['context_hash']
    assert auth_client.post(url(rule), json={'context_hash': context}).status_code == 200
    rule.body_text += '\n# changed';db_session.commit()
    fresh = auth_client.get(url(rule)).json()
    assert fresh['stale'] and fresh['suggestion'] is None
    assert auth_client.post(url(rule), json={'context_hash': context}).status_code == 409


def test_readonly_and_disabled_model(auth_client, client_as, rule):
    read = client_as({'siem':'read'})
    response = read.get(url(rule))
    assert response.status_code == 200
    assert read.post(url(rule), json={'context_hash':response.json()['context_hash']}).status_code == 403
    assert auth_client.post(url(rule), json={'context_hash':response.json()['context_hash']}).status_code == 409


def test_external_model_cannot_receive_source(auth_client, rule):
    assert auth_client.put('/api/settings/llm', json={'tasks':{'rule_rewrite':{'provider':'deepseek','model':'remote'}}}).status_code == 422


def test_model_error_preserves_previous_suggestion(auth_client, rule, monkeypatch):
    from kbaudit.attack.provider import ModelError
    fake(auth_client, monkeypatch)
    context = auth_client.get(url(rule)).json()['context_hash']
    assert auth_client.post(url(rule), json={'context_hash':context}).status_code == 200
    def fail(*a, **kw):
        raise ModelError('secret diagnostic')
    monkeypatch.setattr(rule_rewrite.OllamaCompletion, 'complete', fail)
    response = auth_client.post(url(rule), json={'context_hash':context})
    assert response.status_code == 502 and 'secret diagnostic' not in response.text
    assert auth_client.get(url(rule)).json()['suggestion']['code'] == CODE


def test_missing_source_and_unknown_rule(auth_client, db_session, rule):
    rule.body_text = '';db_session.commit()
    assert auth_client.get(url(rule)).status_code == 422
    assert auth_client.get(url(rule).replace(UUID, 'b'*32)).status_code == 404


def test_complete_generation_requires_stop(monkeypatch):
    from kbaudit.attack.provider import ModelError, OllamaCompletion, OllamaSettings
    monkeypatch.setattr('kbaudit.attack.provider._post_json', lambda *a: {'response':'{}','done':True,'done_reason':'length'})
    with pytest.raises(ModelError):
        OllamaCompletion(OllamaSettings(base_url='http://local')).complete('test', {}, require_complete=True, options={'num_ctx':65536})


def test_source_changed_during_generation_is_not_saved(auth_client, db_session, rule, monkeypatch):
    fake(auth_client, monkeypatch)
    context = auth_client.get(url(rule)).json()['context_hash']
    def change_source(*args, **kwargs):
        rule.body_text += '\n# concurrently updated'
        db_session.commit()
        return json.dumps(answer())
    monkeypatch.setattr(rule_rewrite.OllamaCompletion, 'complete', change_source)
    assert auth_client.post(url(rule), json={'context_hash': context}).status_code == 409
    assert auth_client.get(url(rule)).json()['suggestion'] is None


def test_oversized_source_is_rejected_without_calling_model(auth_client, db_session, rule, monkeypatch):
    seen = fake(auth_client, monkeypatch)
    rule.body_text = SOURCE + '#' * 30000
    db_session.commit()
    assert auth_client.get(url(rule)).status_code == 422
    assert auth_client.post(url(rule), json={'context_hash': '0' * 64}).status_code == 422
    assert seen == []


def test_duplicate_generation_is_rejected(auth_client, rule, monkeypatch):
    seen = fake(auth_client, monkeypatch)
    context = auth_client.get(url(rule)).json()['context_hash']
    key = rule_rewrite.cache_key(rule.snapshot_id, rule.uuid)
    rule_rewrite._ACTIVE.add(key)
    try:
        assert auth_client.post(url(rule), json={'context_hash': context}).status_code == 409
        assert seen == []
    finally:
        rule_rewrite._ACTIVE.discard(key)


def test_ollama_completion_options_and_finish(monkeypatch):
    from kbaudit.attack.provider import OllamaCompletion, OllamaSettings
    seen = []
    def post(url, body, timeout):
        seen.append(body)
        return {'response': '{}', 'done': True, 'done_reason': 'stop'}
    monkeypatch.setattr('kbaudit.attack.provider._post_json', post)
    model = OllamaCompletion(OllamaSettings(base_url='http://local:11434', model='coder'))
    assert model.complete('test', {}, require_complete=True, options={'num_ctx': 65536}) == '{}'
    assert seen[0]['options'] == {'temperature': 0, 'num_ctx': 65536}


@pytest.mark.parametrize('code', [
    'event Login:\n filter { msgid == "4624" }\nrule Example: Login\nemit {',
    'event Login:\n # TODO: implement filter\nrule Example: Login\nemit {}',
    CODE.replace('$correlation_name = "Example"', '$correlation_name = "Example'),
])
def test_unclosed_blocks_and_placeholders_rejected(auth_client, rule, monkeypatch, code):
    fake(auth_client, monkeypatch, answer(code))
    context = auth_client.get(url(rule)).json()['context_hash']
    assert auth_client.post(url(rule), json={'context_hash': context}).status_code == 502


def test_quoted_braces_and_comments_are_not_structure():
    code = CODE.replace('"Example"', '"Example {"') + '\n# ignored }\n/* ignored { */'
    rule_rewrite.validate_code(SOURCE, code)
