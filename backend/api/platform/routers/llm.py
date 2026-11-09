"""Ручки общих настроек модели: /api/settings/llm.

Пустой адрес модели — законное состояние: без неё работает всё, кроме
предложений по разметке. Поэтому сохранение не требует ни адреса, ни его
доступности, а проверка вынесена в отдельную ручку.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy.orm import Session

from api.crypto import SecretUnreadable, decrypt, encrypt
from api.db.base import get_db
from api.db.models import AppSetting, AppUser
from api.deps import get_current_user
from api.llm_settings import LLM_KEY, REMOTE_URLS, LlmSettings, load_llm
from api.llm_tasks import TASKS, TaskAssignment, TaskId
from api.settings import get_settings
from kbaudit.attack import deepseek, openrouter
from kbaudit.attack.provider import ModelError, OllamaCompletion, OllamaEmbedder, OllamaSettings

router = APIRouter(prefix="/llm", tags=["settings"])


def _api_key(db: Session, provider: str, supplied: str | None) -> str:
    if supplied is not None:
        return supplied.strip()
    stored = db.get(AppSetting, f"llm.{provider}_key")
    return decrypt(stored.value_json if stored else "")


class ModelsRequest(BaseModel):
    api_key: str | None = Field(default=None, repr=False)
    provider: Literal["ollama", "openrouter", "deepseek"] = "ollama"
    base_url: str = ""


@router.post("/models")
def list_models(payload: ModelsRequest, _user: AppUser = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, list[str]]:
    if payload.provider == "deepseek":
        try:
            key = _api_key(db, payload.provider, payload.api_key)
            if not key:
                raise HTTPException(422, "Введите API-ключ DeepSeek")
            return deepseek.models(key)
        except SecretUnreadable as exc:
            raise HTTPException(400, str(exc)) from None
        except ModelError as exc:
            raise HTTPException(502, str(exc)) from None
    if payload.provider == "openrouter":
        try:
            return openrouter.models()
        except ModelError as exc:
            raise HTTPException(502, str(exc)) from None
    url = payload.base_url.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.query or parsed.fragment:
        raise HTTPException(422, "Укажите адрес Ollama в формате http://хост:11434")
    try:
        with urllib.request.urlopen(url + "/api/tags", timeout=10) as response:
            raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError("too large")
        data = json.loads(raw)
        models = data["models"]
        if not isinstance(models, list) or any(not isinstance(m, dict) or not isinstance(m.get("name"), str) or not m["name"].strip() for m in models):
            raise ValueError("invalid models")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise HTTPException(502, f"Не удалось получить список моделей Ollama ({type(exc).__name__})") from None
    except (ValueError, KeyError, TypeError):
        raise HTTPException(502, "Ollama вернул некорректный список моделей") from None
    return {"models": sorted({m["name"] for m in models})}


class TestLlmRequest(BaseModel):
    task: TaskId | None = None
    assignment: TaskAssignment | None = None
    think: bool = False
    provider: Literal["ollama", "openrouter", "deepseek"] = "ollama"
    api_key: str | None = Field(default=None, repr=False)
    embed_model: str = ""
    base_url: str = ""
    model: str = ""
    #: Щедро по умолчанию: первый запрос после простоя грузит веса в память.
    #: На живом стенде холодный старт qwen3:8b занял 42 секунды, и проверка
    #: с коротким таймаутом объявила бы рабочую модель недоступной.
    timeout: int = Field(default=90, ge=1, le=300)


class TestLlmResponse(BaseModel):
    ok: bool
    latency_ms: int | None = None
    error: str | None = None


@router.get("", response_model=LlmSettings)
def get_llm(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> LlmSettings:
    return load_llm(db)


class LlmUpdate(LlmSettings):
    key_updates: dict[Literal["openrouter", "deepseek"], str | None] = Field(default_factory=dict, repr=False)
    api_key: str | None = Field(default=None, repr=False)


@router.put("", status_code=status.HTTP_204_NO_CONTENT)
def put_llm(payload: LlmUpdate, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> None:
    row = db.get(AppSetting, LLM_KEY) or AppSetting(key=LLM_KEY)
    updates: dict[str, str | None] = {provider: value for provider, value in payload.key_updates.items()}
    if payload.provider in REMOTE_URLS and payload.api_key is not None:
        updates.setdefault(payload.provider, payload.api_key)
    if any(value and value.strip() for value in updates.values()) and not get_settings().session_secret:
        raise HTTPException(400, "Для хранения API-ключа задайте STOOLS_SESSION_SECRET")
    for provider, value in updates.items():
        if value is None:
            continue
        key_name = f"llm.{provider}_key"
        key = db.get(AppSetting, key_name) or AppSetting(key=key_name)
        key.value_json = encrypt(value.strip())
        key.updated_by = user.login
        db.add(key)
    current = LlmSettings.model_validate_json(row.value_json) if row.value_json else LlmSettings()
    changes = payload.model_dump(exclude_unset=True, exclude={"api_key", "has_api_key", "api_keys", "key_updates", "task_catalog"})
    if 'tasks' in changes:
        changes['tasks'] = {**{name: config.model_dump() for name, config in current.tasks.items()}, **changes['tasks']}
    merged = {**current.model_dump(exclude={'task_catalog'}), **changes}
    row.value_json = LlmSettings.model_validate(merged).model_dump_json(exclude={"has_api_key", "api_keys", "task_catalog"})
    row.updated_by = user.login
    db.add(row)
    db.commit()


@router.post("/test", response_model=TestLlmResponse)
def test_llm(payload: TestLlmRequest, _user: AppUser = Depends(get_current_user), db: Session = Depends(get_db)) -> TestLlmResponse:
    """Проверка доступности модели до сохранения.

    Настройка, о неработоспособности которой узнают через час на фоновой
    задаче, — плохая настройка. Обращение идёт по адресу из запроса, а не
    из сохранённых настроек: проверяют то, что собираются сохранить.
    """
    if payload.task is not None:
        settings = load_llm(db)
        config = payload.assignment or settings.task_config(payload.task)
        # Explicit connection tests may run before enabling or saving a task.
        settings.enabled = True
        if "base_url" in payload.model_fields_set:
            settings.base_url = payload.base_url
        settings.tasks[payload.task] = config.model_copy(update={'enabled': True})
        if payload.api_key is not None and config.provider in REMOTE_URLS:
            settings._stored_keys[config.provider] = encrypt(payload.api_key.strip())
        started = time.monotonic()
        try:
            runtime = settings.for_task(payload.task, data_class=TASKS[payload.task]['data_class'])
            if TASKS[payload.task]['kind'] == 'embedding':
                OllamaEmbedder(runtime).embed(['Connection test'])
            else:
                OllamaCompletion(runtime).complete('Return JSON: {"ok": true}',
                    {'type': 'object', 'properties': {'ok': {'type': 'boolean'}}, 'required': ['ok']})
        except (ModelError, SecretUnreadable) as exc:
            return TestLlmResponse(ok=False, error=str(exc))
        return TestLlmResponse(ok=True, latency_ms=int((time.monotonic() - started) * 1000))
    key = ""
    if payload.provider in REMOTE_URLS:
        try:
            key = _api_key(db, payload.provider, payload.api_key)
        except SecretUnreadable as exc:
            return TestLlmResponse(ok=False, error=str(exc))
        if not key:
            return TestLlmResponse(ok=False, error=f"Введите API-ключ {'DeepSeek' if payload.provider == 'deepseek' else 'OpenRouter'}")
    if payload.provider in REMOTE_URLS and not payload.model.strip():
        return TestLlmResponse(ok=False, error="Выберите модель из списка")
    if payload.provider == "ollama" and not payload.base_url.strip():
        return TestLlmResponse(ok=False, error="адрес модели не задан")
    provider = OllamaCompletion(
        OllamaSettings(
            provider=payload.provider, api_key=SecretStr(key),
            base_url=REMOTE_URLS.get(payload.provider, payload.base_url), model=payload.model or "qwen3:8b-q4_K_M",
            timeout=payload.timeout, think=payload.think,
        )
    )
    started = time.monotonic()
    try:
        provider.complete(
            "Ответь одним словом: готов.",
            {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]},
        )
    except ModelError as exc:
        return TestLlmResponse(ok=False, error=str(exc))
    return TestLlmResponse(ok=True, latency_ms=int((time.monotonic() - started) * 1000))
