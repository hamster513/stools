import io
import json
import urllib.error

import pytest

from api.db.models import AppSetting
from api.llm_settings import load_llm
from kbaudit.attack import openrouter
from kbaudit.attack.provider import ModelError, OllamaCompletion, OllamaEmbedder, OllamaSettings

@pytest.fixture(autouse=True)
def clear_model_cache():
    openrouter._model_parameters.cache_clear()
    yield
    openrouter._model_parameters.cache_clear()


KEY = "test-openrouter-secret"
URL = "/api/settings/llm"


def test_key_encrypted_preserved_and_removed(auth_client, db_session):
    settings = auth_client.get(URL).json()
    settings.update(provider="openrouter", model="test/chat", embed_model="test/embed", api_key=KEY)
    assert auth_client.put(URL, json=settings).status_code == 204
    stored = db_session.get(AppSetting, "llm.openrouter_key").value_json
    assert stored.startswith("enc:") and KEY not in stored
    response = auth_client.get(URL)
    assert KEY not in response.text and "api_key" not in response.json()
    assert response.json()["has_api_key"]
    assert load_llm(db_session).to_provider().api_key.get_secret_value() == KEY
    assert KEY not in load_llm(db_session).model_dump_json()
    assert auth_client.put(URL, json=response.json()).status_code == 204
    db_session.expire_all()
    assert load_llm(db_session).configured
    assert auth_client.put(URL, json={**response.json(), "api_key": ""}).status_code == 204
    db_session.expire_all()
    assert not load_llm(db_session).configured


def test_openrouter_saved_key_test_and_catalog(auth_client, monkeypatch):
    payload = {"provider": "openrouter", "model": "test/chat", "api_key": KEY}
    assert auth_client.put(URL, json=payload).status_code == 204
    calls = []
    def request(path, **kwargs):
        calls.append((path, kwargs))
        if path == "/models":
            return {"data": [{"id": "test/chat", "supported_parameters": ["structured_outputs"]}, {"id": "no-json"}]}
        if path == "/embeddings/models":
            return {"data": [{"id": "test/embed"}]}
        return {"choices": [{"message": {"content": '{"ok":true}'}}]}
    monkeypatch.setattr(openrouter, "request", request)
    assert auth_client.post(URL + "/models", json={"provider": "openrouter"}).json() == {"models": ["no-json", "test/chat"], "embedding_models": ["test/embed"]}
    assert auth_client.post(URL + "/test", json={"provider": "openrouter", "model": "test/chat"}).json()["ok"]
    assert calls[-1][1]["key"] == KEY
    assert auth_client.post(URL + "/test", json={**payload, "api_key": "replacement"}).json()["ok"]
    assert calls[-1][1]["key"] == "replacement"


def test_provider_routes_to_openrouter_and_orders_embeddings(monkeypatch):
    calls = []
    def request(path, **kwargs):
        calls.append((path, kwargs))
        if path == "/embeddings":
            return {"data": [{"index": 1, "embedding": [3, 4]}, {"index": 0, "embedding": [1, 2]}]}
        return {"choices": [{"message": {"content": '{"ok":true}'}}]}
    monkeypatch.setattr(openrouter, "request", request)
    monkeypatch.setattr(openrouter, "_model_parameters", lambda bucket: {"qwen3:8b-q4_K_M": ["structured_outputs"]})
    settings = OllamaSettings(provider="openrouter", base_url="https://openrouter.ai/api/v1", api_key=KEY)
    assert OllamaCompletion(settings).complete("test", {"type": "object"}) == '{"ok":true}'
    assert OllamaEmbedder(settings).embed(["a", "b"]) == [[1, 2], [3, 4]]
    assert all(kwargs["key"] == KEY for _, kwargs in calls)
    assert KEY not in repr(settings)
    monkeypatch.setattr(openrouter, "request", lambda *a, **kw: {"data": [{"index": 0, "embedding": [1]}]})
    with pytest.raises(ModelError):
        OllamaEmbedder(settings).embed(["a", "b"])


def test_transport_fixed_destination_auth_and_safe_errors(monkeypatch):
    seen = []
    def get(req, timeout):
        seen.append(req)
        return io.BytesIO(b'{"data":[]}')
    monkeypatch.setattr(openrouter.urllib.request, "urlopen", get)
    openrouter.request("/embeddings", key=KEY, body={"input": ["hello"]})
    assert seen[0].full_url == "https://openrouter.ai/api/v1/embeddings"
    assert seen[0].get_header("Authorization") == "Bearer " + KEY
    def fail(*args, **kwargs):
        raise urllib.error.HTTPError("url", 401, KEY, {}, io.BytesIO(KEY.encode()))
    monkeypatch.setattr(openrouter.urllib.request, "urlopen", fail)
    with pytest.raises(ModelError) as error:
        openrouter.request("/models", key=KEY)
    assert KEY not in str(error.value)


@pytest.mark.parametrize(("parameters", "expected"), [
    (["response_format"], {"type": "json_object"}),
    ([], None),
    (["structured_outputs"], {"type": "json_schema"}),
])
def test_free_model_format_matches_capabilities(monkeypatch, parameters, expected):
    model = "google/gemma-4-31b-it:free"
    monkeypatch.setattr(openrouter, "_model_parameters", lambda bucket: {model: parameters})
    bodies = []
    def request(path, **kwargs):
        bodies.append(kwargs["body"])
        return {"choices": [{"message": {"content": '{"ok":true}'}}]}
    monkeypatch.setattr(openrouter, "request", request)
    settings = OllamaSettings(provider="openrouter", base_url=openrouter.BASE_URL, api_key=KEY, model=model)
    assert OllamaCompletion(settings).complete("test", {"type": "object"}) == '{"ok":true}'
    body = bodies[0]
    if expected is None:
        assert "response_format" not in body
    else:
        assert body["response_format"]["type"] == expected["type"]
    assert "schema" in body["messages"][0]["content"]
    assert body["model"] == model
    assert "temperature" not in body


def test_free_model_in_catalog(monkeypatch):
    model = "google/gemma-4-31b-it:free"
    monkeypatch.setattr(openrouter, "request", lambda path: {"data": [
        {"id": model, "supported_parameters": ["response_format"], "architecture": {"output_modalities": ["text"]}},
        {"id": "image-only", "architecture": {"output_modalities": ["image"]}},
    ]} if path == "/models" else {"data": []})
    assert openrouter.models()["models"] == [model]
