"""Проверки паков распространённости и их разложения по уровням."""
from __future__ import annotations

import json

from kbaudit.attack.bundle import load_default
from kbaudit.attack.prevalence import (
    LEVEL_MAX,
    PREVALENCE,
    SIGHTINGS,
    levels,
    load,
    load_revoked,
    migrate,
    rollup,
)


def _parent_of() -> dict[str, str]:
    return {t.technique_id: t.parent_id for t in load_default().techniques if t.parent_id}


def test_levels_split_skewed_distribution() -> None:
    """Перекос не должен схлопывать всё в один уровень.

    Реальное распределение — максимум под двести тысяч при медиане
    в шесть десятков. Равные интервалы отправили бы почти всё в первый
    уровень, и раскраска перестала бы что-либо различать.
    """
    scores = {f"T{i:04d}": i for i in range(1, 101)}
    scores["T9999"] = 200_000
    result = levels(scores)
    assert set(result.values()) == {1, 2, 3, 4}
    assert result["T9999"] == LEVEL_MAX
    # Ни один уровень не должен забрать себе почти всё.
    counts = [list(result.values()).count(n) for n in (1, 2, 3, 4)]
    assert max(counts) < len(result) * 0.75


def test_levels_ignore_zero() -> None:
    """Ноль — это «данных нет», а не «редко».

    У техник разведки ноль наблюдений означает, что сенсор их не видит
    в принципе. Уровень «редко» сообщал бы неправду.
    """
    assert levels({"T1000": 0, "T1001": 5}) == {"T1001": 1}
    assert levels({"T1000": 0}) == {}


def test_rollup_folds_subtechniques_into_parent() -> None:
    result = rollup({"T1059.001": 10, "T1059.003": 5, "T1105": 2}, {"T1059.001": "T1059", "T1059.003": "T1059"})
    assert result == {"T1059": 15, "T1105": 2}


def test_migrate_follows_chain_and_gives_up() -> None:
    live = {"T1685"}
    assert migrate("T1562.001", {"T1562.001": "T1562", "T1562": "T1685"}, live) == "T1685"
    assert migrate("T1685", {}, live) == "T1685"
    assert migrate("T9999", {}, live) is None
    # Цикл в чужих данных не должен вешать разбор.
    assert migrate("A", {"A": "B", "B": "A"}, live) is None


def test_group_counts_never_exceed_existing_groups() -> None:
    """Число группировок у техники не может превышать их общее число.

    Родительская сводка считается отдельно, а не суммой по подтехникам:
    группировка, применяющая три подтехники одного семейства, остаётся
    одной группировкой. Суммирование давало у T1059 541 группировку при
    176 существующих, и уровни считались по завышенным числам.
    """
    raw = json.loads(PREVALENCE.read_text(encoding="utf-8"))
    assert raw.get("parents"), "родительская сводка обязана быть в паке"
    biggest = max(item["groups"] for item in raw["parents"])
    assert biggest <= 176, f"группировок у одной техники: {biggest}"

    stats = load(parent_of=_parent_of()).stats
    assert stats["T1059"].groups <= 176


def test_packs_speak_about_live_matrix_only() -> None:
    """В паках не должно быть техник, которых нет в действующей матрице.

    Перенос через `revoked-by` делается на сборке. Если сюда просочился
    отозванный идентификатор, наложение будет молча терять данные.
    """
    live = {t.technique_id for t in load_default().techniques}
    for path in (PREVALENCE, SIGHTINGS):
        raw = json.loads(path.read_text(encoding="utf-8"))
        unknown = {item["id"] for item in raw["techniques"]} - live
        assert not unknown, f"{path.name}: чужие идентификаторы {sorted(unknown)[:5]}"


def test_revoked_map_covers_known_moves() -> None:
    """Карта переносов должна знать перестройку семейства T1562.

    В ATT&CK 19 «Impair Defenses» отозвана целиком и разошлась по новым
    техникам. Это самый крупный перенос, затрагивающий подтверждённую
    разметку заказчика, и он обязан отрабатывать автоматически.
    """
    replaced = load_revoked()
    live = {t.technique_id for t in load_default().techniques}
    assert migrate("T1562.001", replaced, live) == "T1685"
    assert migrate("T1099", replaced, live) == "T1070.006"


def test_sources_disagree_on_subtechniques() -> None:
    """Оба источника на месте и мерят разное — но видно это на подтехниках.

    Расхождение «в ходу у группировок, но сенсорами не замечена» есть
    у 22 подтехник и лишь у 2 родительских. Свёртка в родителя его
    гасит: у семейства почти всегда найдётся хоть одна замеченная ветка.
    Отсюда следует, где эту находку показывать — в карточке техники,
    где видны подтехники, а не в клетке матрицы.
    """
    prevalence = json.loads(PREVALENCE.read_text(encoding="utf-8"))["techniques"]
    seen = {
        item["id"]: item["sightings"]
        for item in json.loads(SIGHTINGS.read_text(encoding="utf-8"))["techniques"]
    }
    invisible = [
        item["id"]
        for item in prevalence
        if "." in item["id"] and item["groups"] >= 25 and seen.get(item["id"], 0) == 0
    ]
    assert len(invisible) > 10, f"ожидалось расхождение на подтехниках, найдено {len(invisible)}"

    rolled = load(parent_of=_parent_of())
    assert rolled.group_level and rolled.sighting_level
