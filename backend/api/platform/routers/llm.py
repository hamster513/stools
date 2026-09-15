"""Ручки общих настроек модели: /api/settings/llm.

Пустой адрес модели — законное состояние: без неё работает всё, кроме
предложений по разметке. Поэтому сохранение не требует ни адреса, ни его
доступности, а проверка вынесена в отдельную ручку.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppSetting, AppUser
from api.deps import get_current_user
from api.llm_settings import LLM_KEY, LlmSettings, load_llm
from kbaudit.attack.provider import ModelError, OllamaCompletion, OllamaSettings

router = APIRouter(prefix="/llm", tags=["settings"])


class TestLlmRequest(BaseModel):
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


@router.put("", status_code=status.HTTP_204_NO_CONTENT)
def put_llm(payload: LlmSettings, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> None:
    row = db.get(AppSetting, LLM_KEY) or AppSetting(key=LLM_KEY)
    row.value_json = payload.model_dump_json()
    row.updated_by = user.login
    db.add(row)
    db.commit()


@router.post("/test", response_model=TestLlmResponse)
def test_llm(payload: TestLlmRequest, _user: AppUser = Depends(get_current_user)) -> TestLlmResponse:
    """Проверка доступности модели до сохранения.

    Настройка, о неработоспособности которой узнают через час на фоновой
    задаче, — плохая настройка. Обращение идёт по адресу из запроса, а не
    из сохранённых настроек: проверяют то, что собираются сохранить.
    """
    if not payload.base_url.strip():
        return TestLlmResponse(ok=False, error="адрес модели не задан")
    provider = OllamaCompletion(
        OllamaSettings(
            base_url=payload.base_url, model=payload.model or "qwen3:8b-q4_K_M",
            timeout=payload.timeout, think=False,
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
