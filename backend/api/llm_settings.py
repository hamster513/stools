"""Настройки модели, общие для платформы.

В базе, а не в переменных окружения, по одной причине: адрес модели задаёт
человек через интерфейс. Настройка, которую меняют пересборкой контейнера,
настройкой не является.

Пустой `base_url` — законное состояние, а не ошибка. Без модели работает
всё, кроме предложений по разметке: разбор, анализ и отбор кандидатов
детерминированы. Исходящих обращений по умолчанию нет.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, PrivateAttr, SecretStr, computed_field, model_validator
from sqlalchemy.orm import Session

from api.crypto import SecretUnreadable, decrypt
from api.db.models import AppSetting
from api.llm_tasks import TASKS, DataClass, TaskAssignment, TaskId, TaskInfo
from kbaudit.attack.provider import ModelError, OllamaSettings

LLM_KEY = "llm"
REMOTE_URLS = {"openrouter": "https://openrouter.ai/api/v1", "deepseek": "https://api.deepseek.com"}


class LlmSettings(BaseModel):
    provider: Literal["ollama", "openrouter", "deepseek"] = "ollama"
    has_api_key: bool = False
    api_keys: dict[str, bool] = Field(default_factory=dict)
    _stored_key: str = PrivateAttr(default="")
    _stored_keys: dict[str, str] = PrivateAttr(default_factory=dict)
    tasks: dict[TaskId, TaskAssignment] = Field(default_factory=dict)
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

    @computed_field  # type: ignore[prop-decorator]
    @property
    def task_catalog(self) -> dict[TaskId, TaskInfo]:
        return TASKS

    @model_validator(mode='after')
    def validate_tasks(self) -> LlmSettings:
        for task, config in self.tasks.items():
            if config.provider not in TASKS[task]['providers']:
                raise ValueError(f"Провайдер не поддерживает задачу: {TASKS[task]['title']}")
        return self

    def task_config(self, task: TaskId) -> TaskAssignment:
        if task not in TASKS:
            raise ModelError('Неизвестная задача LLM')
        if task in self.tasks:
            return self.tasks[task]
        if task == 'rule_rewrite':
            return TaskAssignment(provider='ollama', model=self.model if self.provider == 'ollama' else '',
                                  timeout=self.timeout, think=self.think, local_only=True)
        embedding = task == 'attack_embeddings'
        return TaskAssignment(
            provider='ollama' if embedding and self.provider == 'deepseek' else self.provider,
            model=self.embed_model if embedding else self.model,
            timeout=self.timeout, think=False if embedding else self.think,
        )

    def for_task(self, task: TaskId, *, data_class: DataClass = 'internal') -> OllamaSettings:
        config = self.task_config(task)
        if config.provider != 'ollama' and (data_class not in ('public', 'redacted') or config.local_only):
            raise ModelError('Внутренние данные разрешено обрабатывать только локально')
        if not self.enabled or not config.enabled:
            raise ModelError('Обращения к модели для этой задачи выключены')
        if not config.model.strip():
            raise ModelError('Выберите модель для задачи в настройках LLM')
        if config.provider not in TASKS[task]['providers']:
            raise ModelError('Провайдер не поддерживает эту задачу')
        key = decrypt(self._stored_keys.get(config.provider, '')) if config.provider in REMOTE_URLS else ''
        provider = OllamaSettings(
            provider=config.provider, api_key=SecretStr(key),
            base_url=REMOTE_URLS.get(config.provider, self.base_url),
            model=config.model, embed_model=config.model,
            timeout=config.timeout, think=config.think,
        )
        if not provider.configured:
            raise ModelError('Подключение для задачи не настроено: укажите адрес Ollama или API-ключ провайдера')
        return provider

    def task_configured(self, task: TaskId) -> bool:
        try:
            self.for_task(task, data_class=TASKS[task]['data_class'])
            return True
        except (ModelError, SecretUnreadable):
            return False

    @property
    def configured(self) -> bool:
        return self.enabled and (self.has_api_key if self.provider in REMOTE_URLS else bool(self.base_url.strip()))

    def to_provider(self) -> OllamaSettings:
        return OllamaSettings(
            provider=self.provider,
            api_key=SecretStr(decrypt(self._stored_key) if self.provider in REMOTE_URLS and self.enabled else ""),
            base_url=REMOTE_URLS.get(self.provider, self.base_url) if self.enabled else "",
            embed_base_url=self.base_url if self.enabled else "",
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
    result = LlmSettings() if raw is None else LlmSettings.model_validate_json(raw)
    for provider in REMOTE_URLS:
        key = db.get(AppSetting, f"llm.{provider}_key")
        stored = key.value_json if key else ""
        result.api_keys[provider] = bool(stored)
        result._stored_keys[provider] = stored
        if provider == result.provider:
            result._stored_key = stored
    result.has_api_key = bool(result._stored_key)
    result.tasks = {task: result.task_config(task) for task in TASKS}
    return result
