import io
import json
import urllib.error

import pytest

from api.db.models import AppSetting
from api.llm_settings import load_llm
from kbaudit.attack import deepseek
from kbaudit.attack import provider as provider_module
from kbaudit.attack.provider import ModelError, OllamaCompletion, OllamaEmbedder, OllamaSettings

URL = "/api/settings/llm"
KEY = "fake-deepseek-test-key"


def test_provider_keys_are_encrypted_isolated_preserved_and_removed(auth_client, db_session):
    assert auth_client.put(URL, json={"provider": "openrouter", "api_key": "fake-router-key"}).status_code == 204
    payload = {"provider": "deepseek", "api_key": KEY, "model": "live-model", "base_url": "http://ollama:11434", "embed_model": "bge-m3"}
    assert auth_client.put(URL, json=payload).status_code == 204
    db_session.expire_all()
    stored = db_session.get(AppSetting, "llm.deepseek_key").value_json
    assert stored.startswith("enc:") and KEY not in stored
    response = auth_client.get(URL)
    assert KEY not in response.text and "api_key" not in response.json()
    assert response.json()["api_keys"] == {"openrouter": True, "deepseek": True}
    runtime = load_llm(db_session).to_provider()
    assert runtime.base_url == deepseek.BASE_URL
    assert runtime.embed_base_url == "http://ollama:11434"
    assert runtime.api_key.get_secret_value() == KEY
    assert KEY not in runtime.model_dump_json() and KEY not in repr(runtime)
    assert auth_client.put(URL, json={**response.json(), "provider": "ollama", "api_key": ""}).status_code == 204
    assert not auth_client.get(URL).json()["has_api_key"]
    assert auth_client.put(URL, json=response.json()).status_code == 204
    assert auth_client.get(URL).json()["has_api_key"]
    assert auth_client.put(URL, json={**response.json(), "api_key": ""}).status_code == 204
    assert auth_client.get(URL).json()["api_keys"] == {"openrouter": True, "deepseek": False}
    db_session.expire_all()
    assert not load_llm(db_session).configured
    assert auth_client.put(URL, json={"provider": "openrouter"}).status_code == 204
    db_session.expire_all()
    assert load_llm(db_session).to_provider().api_key.get_secret_value() == "fake-router-key"


def test_models_and_test_use_only_selected_provider_key(auth_client, monkeypatch):
    assert auth_client.put(URL, json={"provider": "openrouter", "api_key": "router-only"}).status_code == 204
    assert auth_client.post(URL + "/models", json={"provider": "deepseek"}).status_code == 422
    assert not auth_client.post(URL + "/test", json={"provider": "deepseek", "model": "live-model"}).json()["ok"]
    calls = []
    def request(path, **kwargs):
        calls.append((path, kwargs))
        if path == "/models":
            return {"data": [{"id": "live-model"}, {"id": "live-model"}, {"id": "future-model", "output_modalities": ["text"]}]}
        return {"choices": [{"message": {"content": '{"ok": true}'}}]}
    monkeypatch.setattr(deepseek, "request", request)
    payload = {"provider": "deepseek", "api_key": KEY, "model": "live-model"}
    assert auth_client.post(URL + "/models", json=payload).json() == {"models": ["future-model", "live-model"], "embedding_models": []}
    assert calls[-1][1]["key"] == KEY
    assert not auth_client.get(URL).json()["api_keys"]["deepseek"]
    assert auth_client.put(URL, json=payload).status_code == 204
    assert auth_client.post(URL + "/models", json={"provider": "deepseek"}).status_code == 200
    assert calls[-1][1]["key"] == KEY
    assert auth_client.post(URL + "/test", json={"provider": "deepseek", "model": "live-model", "think": True}).json()["ok"]
    assert calls[-1][1]["key"] == KEY
    assert calls[-1][1]["body"]["thinking"] == {"type": "enabled"}
    assert auth_client.post(URL + "/test", json={**payload, "api_key": "replacement"}).json()["ok"]
    assert calls[-1][1]["key"] == "replacement"
    assert auth_client.post(URL + "/models", json={"provider": "deepseek", "api_key": ""}).status_code == 422


@pytest.mark.parametrize("think", [True, False])
def test_json_completion_and_local_embeddings_use_separate_transports(monkeypatch, think):
    remote, local = [], []
    def request(path, **kwargs):
        remote.append((path, kwargs))
        return {"choices": [{"message": {"content": '{"ok":true}', "reasoning_content": "ignored"}}]}
    def post(url, body, timeout):
        local.append((url, body, timeout))
        return {"embeddings": [[1, 2]]}
    monkeypatch.setattr(deepseek, "request", request)
    monkeypatch.setattr(provider_module, "_post_json", post)
    s = OllamaSettings(provider="deepseek", api_key=KEY, base_url="http://ignored.test", embed_base_url="http://ollama:11434", model="live-model", embed_model="bge-m3", think=think)
    assert OllamaCompletion(s).complete("test", {"type": "object"}) == '{"ok":true}'
    assert OllamaEmbedder(s).embed(["text"]) == [[1, 2]]
    assert remote[0][0] == "/chat/completions"
    body = remote[0][1]["body"]
    assert body["model"] == "live-model" and body["response_format"] == {"type": "json_object"}
    assert "JSON" in body["messages"][0]["content"]
    assert body["thinking"] == {"type": "enabled" if think else "disabled"}
    assert ("temperature" in body) is (not think)
    assert local[0][0] == "http://ollama:11434/api/embed"
    assert local[0][1] == {"model": "bge-m3", "input": ["text"]}
    assert KEY not in repr(local)
    with pytest.raises(ModelError, match="адрес Ollama"):
        OllamaEmbedder(s.model_copy(update={"embed_base_url": ""})).embed(["text"])


@pytest.mark.parametrize("status, message", [(401, "ключ"), (402, "балансе"), (429, "лимит"), (503, "перегружен")])
def test_errors_hide_provider_payload_and_key(monkeypatch, status, message):
    def fail(req, timeout):
        assert req.full_url == "https://api.deepseek.com/models"
        assert req.get_header("Authorization") == "Bearer " + KEY
        raise urllib.error.HTTPError("url", status, KEY, {}, io.BytesIO(KEY.encode()))
    monkeypatch.setattr(deepseek.urllib.request, "urlopen", fail)
    with pytest.raises(ModelError, match=message) as error:
        deepseek.models(KEY)
    assert KEY not in str(error.value)


@pytest.mark.parametrize("content", ["", "   ", "not json", None])
def test_bad_json_is_reported(monkeypatch, content):
    monkeypatch.setattr(deepseek, "request", lambda *a, **kw: {"choices": [{"message": {"content": content}}]})
    with pytest.raises(ModelError, match="JSON"):
        deepseek.complete(OllamaSettings(api_key=KEY), "test", {})


@pytest.mark.parametrize("data", [None, {}, [{"id": None}], [{"id": ""}]])
def test_malformed_catalog(monkeypatch, data):
    monkeypatch.setattr(deepseek, "request", lambda *a, **kw: {"data": data})
    with pytest.raises(ModelError, match="каталог"):
        deepseek.models(KEY)


def test_transport_sends_json_to_fixed_endpoint(monkeypatch):
    def respond(req, timeout):
        assert req.full_url == "https://api.deepseek.com/chat/completions"
        assert req.get_header("Authorization") == "Bearer " + KEY
        assert json.loads(req.data)["model"] == "live-model"
        return io.BytesIO(b'{"choices":[{"message":{"content":"{\\"ok\\":true}"}}]}')
    monkeypatch.setattr(deepseek.urllib.request, "urlopen", respond)
    settings = OllamaSettings(provider="deepseek", base_url="http://untrusted.test", api_key=KEY, model="live-model")
    assert json.loads(OllamaCompletion(settings).complete("test", {})) == {"ok": True}


@pytest.mark.parametrize("choice", [None, {"finish_reason": "length", "message": {"content": '{"ok":true}'}}])
def test_truncated_or_malformed_completion(monkeypatch, choice):
    monkeypatch.setattr(deepseek, "request", lambda *a, **kw: {"choices": [choice]})
    with pytest.raises(ModelError):
        deepseek.complete(OllamaSettings(api_key=KEY), "test", {})
