"""Распространённость техник: насколько часто их применяют и замечают.

Два источника, и они меряют разное.

`prevalence` — сколько группировок и кампаний ATT&CK применяют технику.
Это курируемые данные: аналитики MITRE читают отчёты и размечают. Версия
совпадает с нашей матрицей, техник охвачено 588 из 697.

`sightings` — телеметрия CTID: 1.48 млн наблюдений за 2021–2023 годы.
Восемьдесят процентов — сырой вывод сенсоров без проверки человеком,
выборка перекошена в сторону США и обрабатывающей промышленности, а сам
файл обрезан на пределе строк Excel. Поэтому он меряет не поведение
атакующих, а то, что выдают сенсоры. Для аудита правил детекта это
уместнее, чем кажется, но подписывать надо именно так.

Ни то ни другое не является «трендом»: оба источника ретроспективны,
телеметрия заморожена в 2023 году. Слово «тренд» здесь не употребляется
намеренно.
"""
from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

#: Пороговые доли для уровней интенсивности. Считаются по ненулевым
#: значениям: техник с нулём больше половины, и включение их в выборку
#: сдвинуло бы все границы в ноль.
_QUANTILES = (0.5, 0.8, 0.95)

#: Уровень «данных нет» отделён от уровня «редко» намеренно. Ноль
#: наблюдений у техники разведки означает, что сенсор её не видит
#: в принципе, а не что её не применяют.
LEVEL_NONE = 0
LEVEL_MAX = 4

PREVALENCE = Path(__file__).with_name("attack_prevalence.json")
SIGHTINGS = Path(__file__).with_name("attack_sightings.json")
REVOKED = Path(__file__).with_name("attack_revoked.json")


class TechniqueStat(BaseModel):
    """Сырые числа по технике, как они пришли из источника."""

    groups: int = 0
    campaigns: int = 0
    last_seen: str | None = None
    sightings: int = 0


class Prevalence(BaseModel):
    """Свод по всем техникам с уже посчитанными уровнями."""

    stats: dict[str, TechniqueStat] = Field(default_factory=dict)
    #: Уровень 0..4 по числу группировок и по телеметрии отдельно.
    group_level: dict[str, int] = Field(default_factory=dict)
    sighting_level: dict[str, int] = Field(default_factory=dict)
    sightings_window: str | None = None

    def level(self, technique_id: str) -> int:
        """Итоговый уровень — больший из двух.

        Максимум, а не среднее: источники покрывают разное, и техника,
        заметная хотя бы по одному, заслуживает внимания. Среднее же
        гасило бы её нулём из второго источника, где данных просто нет.
        """
        return max(
            self.group_level.get(technique_id, LEVEL_NONE),
            self.sighting_level.get(technique_id, LEVEL_NONE),
        )


def levels(scores: dict[str, int]) -> dict[str, int]:
    """Разложить сырые числа по уровням 1..4.

    Квантили, а не равные интервалы: распределение крайне перекошено —
    у телеметрии максимум под двести тысяч при медиане в шесть десятков.
    Равные интервалы отправили бы девяносто девять процентов техник
    в самый бледный уровень, и картинка перестала бы что-либо различать.
    """
    values = sorted(v for v in scores.values() if v > 0)
    if not values:
        return {}
    bounds = [values[min(int(len(values) * q), len(values) - 1)] for q in _QUANTILES]
    out: dict[str, int] = {}
    for technique_id, value in scores.items():
        if value <= 0:
            continue
        level = 1
        for bound in bounds:
            if value > bound:
                level += 1
        out[technique_id] = min(level, LEVEL_MAX)
    return out


def rollup(scores: dict[str, int], parent_of: dict[str, str]) -> dict[str, int]:
    """Свернуть подтехники в родителя.

    Матрица показывает родительские техники, а статистика собрана по
    обеим. Без свёртки техника, вся активность которой размечена
    подтехниками, выглядела бы неприменяемой.
    """
    out: dict[str, int] = {}
    for technique_id, value in scores.items():
        key = parent_of.get(technique_id, technique_id)
        out[key] = out.get(key, 0) + value
    return out


def load_revoked(path: Path = REVOKED) -> dict[str, str]:
    """Карта переносов «отозванная техника → замена»."""
    if not path.is_file():
        return {}
    return dict(json.loads(path.read_text(encoding="utf-8")).get("replaced_by") or {})


def migrate(technique_id: str, replaced_by: dict[str, str], live: set[str]) -> str | None:
    """Идентификатор в терминах действующей матрицы, если он есть.

    Разматывается цепочка: техника могла переезжать не один раз. Предел
    в восемь шагов — страховка от цикла в чужих данных.
    """
    current = technique_id
    for _ in range(8):
        if current in live:
            return current
        nxt = replaced_by.get(current)
        if nxt is None or nxt == current:
            return None
        current = nxt
    return None


def load(
    prevalence_path: Path = PREVALENCE,
    sightings_path: Path = SIGHTINGS,
    parent_of: dict[str, str] | None = None,
) -> Prevalence:
    """Прочитать паки и посчитать уровни.

    С `parent_of` подтехники сворачиваются в родителя — это вид для
    матрицы, где показаны только родительские техники. Без него числа
    остаются при своих техниках: в карточке техники человек сравнивает
    подтехники между собой, и свёртка там уничтожила бы весь смысл.

    Отсутствие файла не ошибка: без паков продукт работает, просто
    не показывает наложение. Так сборка без статистики остаётся рабочей.
    """
    parent_of = parent_of or {}
    stats: dict[str, TechniqueStat] = {}
    groups: dict[str, int] = {}
    seen: dict[str, int] = {}
    window: str | None = None

    if prevalence_path.is_file():
        raw = json.loads(prevalence_path.read_text(encoding="utf-8"))
        if parent_of:
            # Число группировок берётся из готовой родительской сводки,
            # а не складывается по подтехникам: складывать счётчики
            # различных группировок нельзя, одна и та же попала бы
            # в сумму трижды.
            for item in raw.get("parents") or []:
                entry = stats.setdefault(item["id"], TechniqueStat())
                entry.groups = int(item.get("groups") or 0)
                entry.campaigns = int(item.get("campaigns") or 0)
                groups[item["id"]] = entry.groups
        for item in raw.get("techniques") or []:
            key = parent_of.get(item["id"], item["id"])
            entry = stats.setdefault(key, TechniqueStat())
            if not parent_of:
                # Без свёртки каждая запись сама себе итог, складывать
                # ничего не надо — и подтехники получают свои числа,
                # а не унаследованные от родителя.
                entry.groups = int(item.get("groups") or 0)
                entry.campaigns = int(item.get("campaigns") or 0)
                groups[key] = entry.groups
            last = item.get("last_seen")
            if last and (entry.last_seen is None or last > entry.last_seen):
                entry.last_seen = last

    if sightings_path.is_file():
        raw = json.loads(sightings_path.read_text(encoding="utf-8"))
        window = raw.get("window")
        for item in raw.get("techniques") or []:
            key = parent_of.get(item["id"], item["id"])
            entry = stats.setdefault(key, TechniqueStat())
            entry.sightings += int(item.get("sightings") or 0)
            seen[key] = seen.get(key, 0) + int(item.get("sightings") or 0)

    return Prevalence(
        stats=stats,
        group_level=levels(groups),
        sighting_level=levels(seen),
        sightings_window=window,
    )
