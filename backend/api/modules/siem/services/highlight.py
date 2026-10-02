"""Разметка тела правила: где в коде сидят находки.

Тело правила и так показывается целиком, поэтому подсветка ничего нового
не раскрывает — она отвечает на вопрос «где именно», который иначе
решается поиском по глазам среди сотни замечаний.

Позиции считаются на сервере, потому что значения находок клиенту
не отдаются: он получает только отрезки и класс каждого.
"""
from __future__ import annotations

from pydantic import BaseModel

#: Значения короче этого в теле не подсвечиваются: одиночный символ
#: или пара цифр совпадёт где угодно, и подсветка превратится в рябь.
MIN_VALUE_LEN = 2


class Span(BaseModel):
    """Отрезок тела правила, занятый значением находки."""

    start: int
    end: int
    kind: int
    #: Код общего статуса находки.
    status: str
    #: Учитывается ли статус в подсчётах (настройка `counted`): неучитываемое
    #: замечание — принятый риск, ложное срабатывание — гасится.
    counted: bool = True


def _occurrences(body: str, value: str) -> list[tuple[int, int]]:
    """Вхождения значения в теле — только внутри кавычек.

    Литералы в теле правила всегда закавычены, а поиск голой подстроки
    подсветил бы имя поля, кусок пути и вообще что угодно: значение
    `host` встречается в `event_src.host` и в `hostname`.
    """
    needle = f'"{value}"'
    out: list[tuple[int, int]] = []
    start = 0
    while (index := body.find(needle, start)) >= 0:
        out.append((index + 1, index + 1 + len(value)))
        start = index + 1
    return out


def spans_for(body: str | None, findings: list[dict[str, object]]) -> list[Span]:
    """Отрезки подсветки, без пересечений и в порядке появления.

    При наложении выигрывает более тяжёлый класс: если одно и то же место
    попало и в «дублирует список», и в «одиночный литерал», показать надо
    первое — оно и означает работу, которую предстоит сделать.
    """
    if not body:
        return []

    best: dict[tuple[int, int], Span] = {}
    for finding in findings:
        value = str(finding.get("value") or "")
        if len(value) < MIN_VALUE_LEN:
            continue
        kind = int(finding.get("kind") or 0)
        status = str(finding.get("status") or "new")
        counted = bool(finding.get("counted", True))
        for start, end in _occurrences(body, value):
            current = best.get((start, end))
            if current is None or kind < current.kind:
                best[(start, end)] = Span(
                    start=start, end=end, kind=kind, status=status, counted=counted
                )

    spans = sorted(best.values(), key=lambda s: (s.start, -s.end))
    # Вложенные и перекрывающиеся отрезки клиент нарисовать не сможет:
    # оставляем первый, следующий начинается после конца предыдущего.
    out: list[Span] = []
    for span in spans:
        if out and span.start < out[-1].end:
            continue
        out.append(span)
    return out
