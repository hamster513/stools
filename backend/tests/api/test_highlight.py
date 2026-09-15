"""Подсветка находок в теле правила.

Значения здесь выдуманы: тест про сокрытие данных сам их содержать
не должен, а этот — про то, где данные показываются.
"""
from api.modules.siem.services.highlight import spans_for

BODY = 'filter { subject.account.name == "srv99" and dst.ip == "10.0.0.1" }'


def finding(kind: int, value: str, status: str = "open") -> dict[str, object]:
    return {"kind": kind, "value": value, "status": status}


def test_span_points_at_the_value_not_at_the_quotes() -> None:
    """Подсвечивается само значение: кавычки — часть синтаксиса,
    и красить их незачем."""
    spans = spans_for(BODY, [finding(1, "srv99")])
    assert len(spans) == 1
    assert BODY[spans[0].start : spans[0].end] == "srv99"
    assert spans[0].kind == 1


def test_only_quoted_occurrences_count() -> None:
    """Поиск голой подстроки подсветил бы имя поля и вообще что угодно:
    `host` встречается и в `event_src.host`, и в `hostname`."""
    body = 'filter { event_src.host == "host" }'
    spans = spans_for(body, [finding(2, "host")])
    assert len(spans) == 1
    assert spans[0].start == body.index('"host"') + 1


def test_every_occurrence_is_marked() -> None:
    body = 'filter { a == "dc01" or b == "dc01" }'
    assert len(spans_for(body, [finding(1, "dc01")])) == 2


def test_heavier_class_wins_on_the_same_place() -> None:
    """Если место попало и в «дублирует список», и в «одиночный литерал»,
    показать надо первое: оно и означает работу."""
    spans = spans_for(BODY, [finding(5, "srv99"), finding(1, "srv99")])
    assert len(spans) == 1
    assert spans[0].kind == 1


def test_status_travels_with_the_span() -> None:
    """Принятое замечание гасится, а не исчезает: решение принято,
    но код остался прежним."""
    spans = spans_for(BODY, [finding(1, "srv99", status="accepted")])
    assert spans[0].status == "accepted"


def test_spans_never_overlap() -> None:
    """Клиент рисует отрезки подряд: перекрытие он нарисовать не сможет."""
    body = 'filter { a == "abcdef" }'
    spans = spans_for(body, [finding(1, "abcdef"), finding(2, "abc")])
    assert len(spans) == 1


def test_too_short_values_are_not_highlighted() -> None:
    """Одиночный символ совпадёт где угодно, и подсветка станет рябью."""
    assert spans_for('a == "x"', [finding(5, "x")]) == []


def test_value_absent_from_the_body_yields_nothing() -> None:
    """Находка могла прийти из другого объекта или из фильтра."""
    assert spans_for(BODY, [finding(1, "нет такого")]) == []


def test_empty_body_is_not_an_error() -> None:
    assert spans_for(None, [finding(1, "srv99")]) == []
    assert spans_for("", [finding(1, "srv99")]) == []


def test_spans_come_in_reading_order() -> None:
    spans = spans_for(BODY, [finding(2, "10.0.0.1"), finding(1, "srv99")])
    assert [s.kind for s in spans] == [1, 2], "по положению в теле, а не по классу"
