import json

import pytest

from api.modules.vm.services.trends.analyze import analyze_text


def test_chinese_summary_requires_quote_from_original():
    original = '研究人员发现漏洞已经在野利用。'
    class Provider:
        def complete(self, prompt, schema):
            assert original in prompt
            assert schema['properties']['quote']
            return json.dumps({'summary_ru': 'Исследователи сообщают об эксплуатации', 'quote': '已经在野利用', 'exploitation_claim': True})
    result = analyze_text({'text': original}, Provider())
    assert result['exploitation_claim']
    class Fabricated:
        def complete(self, prompt, schema):
            return json.dumps({'summary_ru': 'test', 'quote': 'invented evidence', 'exploitation_claim': True})
    with pytest.raises(ValueError, match='цитату'):
        analyze_text({'text': original}, Fabricated())


def test_telegram_origin_never_reaches_model_after_source_edit(db_session, monkeypatch):
    from types import SimpleNamespace

    from api.modules.vm.services.trends import analyze
    from api.modules.vm.services.trends.ingest import apply_page
    from tests.vm.test_trend_sync import page
    data = page()
    data['events'][0]['payload'].update(adapter='telegram', llm_allowed=False)
    apply_page(db_session, data)
    source = {**data['events'][0], 'seq': 3, 'revision': 2,
              'payload': {**data['events'][0]['payload'], 'adapter': 'rss', 'llm_allowed': True}}
    apply_page(db_session, {**data, 'until_seq': 3, 'next_cursor': 3, 'events': [source]})
    monkeypatch.setattr(analyze, 'load_llm', lambda db: SimpleNamespace(configured=True, model='test', to_provider=lambda: None))
    class Provider:
        def complete(self, *args):
            pytest.fail('Telegram content sent to LLM')
    monkeypatch.setattr(analyze, 'OllamaCompletion', lambda config: Provider())
    analyze.process_pending(db_session)
