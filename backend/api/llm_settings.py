"""Настройки модели, общие для платформы.

В базе, а не в переменных окружения, по одной причине: адрес модели задаёт
человек через интерфейс. Настройка, которую меняют пересборкой контейнера,
настройкой не является.

Пустой `base_url` — законное состояние, а не ошибка. Без модели работает
всё, кроме предложений по разметке: разбор, анализ и отбор кандидатов
детерминированы. Исходящих обращений по умолчанию нет.
"""
from __future__ import annotations

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.db.models import AppSetting
from kbaudit.attack.provider import OllamaSettings

LLM_KEY = "llm"


class LlmSettings(BaseModel):
    base_url: str = ""
    model: str = "qwen3:8b-q4_K_M"
    embed_model: str = "bge-m3"
    #: Режим рассуждения замедляет ответ в разы; влияние на точность
    #: проверяется на эталонной разметке, а не предполагается.
    think: bool = False
    timeout: int = Field(default=180, ge=5, le=1800)
    #: Выключатель отдельно от адреса: адрес можно сохранить, а обращения
    #: временно прекратить, не теряя настройку.
    enabled: bool = True

    @property
    def configured(self) -> bool:
        return self.enabled and bool(self.base_url.strip())

    def to_provider(self) -> OllamaSettings:
        return OllamaSettings(
            base_url=self.base_url if self.enabled else "",
            model=self.model,
            embed_model=self.embed_model,
            timeout=self.timeout,
            think=self.think,
        )


def read_setting(db: Session, key: str) -> str | None:
    """JSON настройки или None, если её нет.

    «Нет записи», «пустое значение» и «пустой объект» — одно и то же
    состояние: настройку не задавали, и читать её нужно умолчаниями.
    Проверка одна на всех, кто хранит настройки в `app_setting`.
    """
    row = db.get(AppSetting, key)
    if row is None or not row.value_json or row.value_json == "{}":
        return None
    return row.value_json


def load_llm(db: Session) -> LlmSettings:
    raw = read_setting(db, LLM_KEY)
    return LlmSettings() if raw is None else LlmSettings.model_validate_json(raw)
