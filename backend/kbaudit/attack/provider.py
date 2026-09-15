"""Обращение к языковой модели.

Единственное место в ядре, которое ходит в сеть, и только когда адрес
задан явно. Без настройки инструмент работает: разбор, анализ, отбор
кандидатов — всё это детерминированно и обходится без модели.

Провайдер описан протоколом, чтобы разметку можно было проверять без
сети и без весов: подставляется предсказуемая заглушка.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Protocol

from pydantic import BaseModel

from kbaudit.attack.bundle import Technique
from kbaudit.attack.candidates import Candidate
from kbaudit.attack.payload import GroupPayload
from kbaudit.attack.prompt import (
    GroupSuggestion,
    TechniqueSuggestion,
    build_prompt,
    response_schema,
)

DEFAULT_TIMEOUT = 180


class ModelError(RuntimeError):
    """Модель недоступна или ответила не по схеме."""


class Completion(Protocol):
    """Минимальный контракт: промпт и схема на входе, разбираемый JSON на выходе."""

    def complete(self, prompt: str, schema: dict[str, Any]) -> str: ...


class OllamaSettings(BaseModel):
    #: Пустой адрес означает «модель не настроена» — не ошибку.
    base_url: str = ""
    model: str = "qwen3:8b-q4_K_M"
    #: Модель эмбеддингов для отбора кандидатов. Отдельная от генеративной:
    #: отбор детерминирован и не требует рассуждающей модели.
    embed_model: str = "bge-m3"
    timeout: int = DEFAULT_TIMEOUT
    #: Режим рассуждения замедляет ответ в разы. Влияние на точность
    #: проверяется на эталонной разметке, а не предполагается.
    think: bool = False

    @property
    def configured(self) -> bool:
        return bool(self.base_url.strip())


def _post_json(url: str, body: dict[str, Any], timeout: int) -> dict[str, Any]:
    """POST с JSON и разбором JSON-ответа.

    Ошибки сети и разбора сводятся к `ModelError` с именем класса
    исключения, без текста: сообщение уходит в интерфейс, а текст
    исключения может нести адрес и содержимое запроса.
    """
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            parsed = json.load(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        raise ModelError(f"модель недоступна: {type(exc).__name__}") from exc
    if not isinstance(parsed, dict):
        raise ModelError("ответ модели не является объектом JSON")
    return parsed


class OllamaCompletion:
    """Провайдер Ollama с ограничением вывода по JSON-схеме."""

    def __init__(self, settings: OllamaSettings) -> None:
        self._settings = settings

    def complete(self, prompt: str, schema: dict[str, Any]) -> str:
        s = self._settings
        if not s.configured:
            raise ModelError("адрес модели не задан")
        body = {
            "model": s.model,
            "prompt": prompt,
            "stream": False,
            "think": s.think,
            # Температура ноль: разметка должна быть воспроизводимой. Одна
            # и та же выгрузка обязана давать один и тот же результат, иначе
            # расхождение между прогонами не отличить от расхождения из-за
            # правки правил.
            "options": {"temperature": 0},
            "format": schema,
        }
        parsed = _post_json(f"{s.base_url.rstrip('/')}/api/generate", body, s.timeout)
        return str(parsed.get("response") or "")


def suggest_techniques(
    payload: GroupPayload,
    candidates: list[Candidate],
    techniques: dict[str, Technique],
    completion: Completion,
    model_name: str | None = None,
    attack_version: str | None = None,
) -> GroupSuggestion:
    """Предложение модели по одной группе.

    Результат — предложение, а не факт: `reviewed_by` остаётся пустым, пока
    человек не подтвердит. Ошибки разметки тихие, неверная техника годами
    живёт в отчёте и никого не смущает.
    """
    allowed = {c.technique_id for c in candidates}
    raw = completion.complete(
        build_prompt(payload, candidates, techniques), response_schema(candidates)
    )
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ModelError("ответ модели не разбирается как JSON") from exc

    suggestions: list[TechniqueSuggestion] = []
    for item in parsed.get("techniques") or []:
        if not isinstance(item, dict):
            continue
        technique_id = item.get("technique_id")
        # Перечисление в схеме уже не даёт назвать чужую технику, но
        # проверка остаётся: схему может не поддержать другой провайдер,
        # и тогда молчаливое доверие обернётся выдуманным идентификатором
        # в базе.
        if technique_id not in allowed:
            continue
        suggestions.append(
            TechniqueSuggestion(
                technique_id=str(technique_id),
                confidence=str(item.get("confidence") or "низкая"),
                evidence=str(item.get("evidence") or ""),
            )
        )

    return GroupSuggestion(
        group=payload.group,
        techniques=suggestions,
        candidates=[c.technique_id for c in candidates],
        model=model_name,
        attack_version=attack_version,
    )


class OllamaEmbedder:
    """Эмбеддер поверх Ollama — детерминированная половина разметки.

    Отдельный класс, а не метод провайдера: отбор кандидатов должен работать
    и тогда, когда генеративная модель не настроена. Векторы техник считаются
    один раз и кэшируются в базе — бандл ATT&CK меняется раз в квартал,
    а разметка запускается на каждой выгрузке.
    """

    def __init__(self, settings: OllamaSettings) -> None:
        self._settings = settings

    def embed(self, texts: list[str]) -> list[list[float]]:
        s = self._settings
        if not s.configured:
            raise ModelError("адрес модели не задан")
        if not texts:
            return []
        parsed = _post_json(
            f"{s.base_url.rstrip('/')}/api/embed",
            {"model": s.embed_model, "input": texts},
            s.timeout,
        )
        vectors = parsed.get("embeddings")
        if not isinstance(vectors, list) or len(vectors) != len(texts):
            # Молчаливо принять короткий ответ — значит сдвинуть векторы
            # относительно техник и получить правдоподобную чушь в разметке.
            raise ModelError("эмбеддер вернул не столько векторов, сколько текстов")
        return [[float(x) for x in v] for v in vectors]
