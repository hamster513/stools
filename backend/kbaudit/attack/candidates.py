"""Отбор техник-кандидатов по близости смысла.

Это детерминированная половина разметки: никакой модели, только арифметика
на векторах. Одна и та же выгрузка всегда даёт одних и тех же кандидатов,
и проверить это можно без GPU и без Ollama.

Языковая модель получает готовый короткий список и выбирает из него —
`technique_id` ограничен перечислением, поэтому назвать несуществующую
технику она не может физически.
"""
from __future__ import annotations

import math
from typing import Protocol

from pydantic import BaseModel, Field

from kbaudit.attack.bundle import Technique

#: Сколько кандидатов класть в промпт. Число подбирается измерением полноты
#: на эталонной разметке, а не берётся на веру: слишком мало — верной техники
#: не окажется в списке, и это невосстановимо; слишком много — растёт контекст
#: и среди близких промахов модель ошибается чаще.
DEFAULT_TOP_K = 15


class Embedder(Protocol):
    """Минимальный контракт эмбеддера.

    Ради него отбор отделён от модели: подстановка предсказуемого эмбеддера
    делает тесты быстрыми и не требует ни сети, ни весов.
    """

    def embed(self, texts: list[str]) -> list[list[float]]: ...


class Candidate(BaseModel):
    technique_id: str
    name: str
    tactics: list[str] = Field(default_factory=list)
    similarity: float


def cosine(a: list[float], b: list[float]) -> float:
    """Косинус угла между векторами: 1 — совпадение смысла, 0 — нет связи."""
    if len(a) != len(b):
        raise ValueError("векторы разной длины")
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


def select_candidates(
    query_vector: list[float],
    techniques: list[Technique],
    vectors: dict[str, list[float]],
    top_k: int = DEFAULT_TOP_K,
) -> list[Candidate]:
    """Ближайшие по смыслу техники, лучшая первой.

    Техники без вектора пропускаются молча: это значит, что бандл новее
    предрасчитанных векторов, и лучше отдать неполный список кандидатов,
    чем не отдать никакого. Расхождение видно по числу векторов и должно
    чиниться пересборкой, а не здесь.
    """
    scored = [
        Candidate(
            technique_id=t.technique_id,
            name=t.name,
            tactics=t.tactics,
            similarity=round(cosine(query_vector, vectors[t.technique_id]), 4),
        )
        for t in techniques
        if t.technique_id in vectors
    ]
    scored.sort(key=lambda c: (-c.similarity, c.technique_id))
    return scored[:top_k]


def recall_at_k(
    selected: dict[str, list[Candidate]],
    expected: dict[str, set[str]],
) -> float:
    """Доля групп, для которых верная техника попала в список кандидатов.

    Это главное число отбора. Ошибка здесь невосстановима: если нужной
    техники нет среди кандидатов, модель выберет лучшее из неправильного —
    и выберет уверенно. Точность выбора можно поправить моделью получше,
    полноту отбора — нельзя ничем.
    """
    if not expected:
        return 0.0
    hits = 0
    for group, wanted in expected.items():
        got = {c.technique_id for c in selected.get(group, [])}
        if wanted & got:
            hits += 1
    return round(hits / len(expected), 4)
