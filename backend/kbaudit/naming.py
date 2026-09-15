"""Определение схемы именования правил по самим именам.

Инструмент не должен знать, кто писал правила. Вендорская схема
(`DEMO_HC_002_029_Impacket`, код `JC-HC-002-029` в описании) — частный
случай, а не допущение: вендор ушёл, а выгрузка осталась, и следующая
может прийти от другого автора с другими соглашениями.

Схема выводится из статистики: имена режутся по разделителю, и для каждой
позиции считается покрытие и число различных значений. Структурный код —
это ведущие позиции, которые есть у всех имён: описание бывает разной
длины, а код одинаковой. Разбиение, дающее одну группу на всю выгрузку
или отдельную группу почти на каждое правило, отбраковывается по оценке —
ни то, ни другое каталогом не является.
"""
from __future__ import annotations

from collections import Counter

from pydantic import BaseModel, Field, computed_field

from kbaudit.models import RuleCode

#: Роли позиций, назначаемые справа налево: последняя структурная позиция —
#: номер правила, перед ней группа, затем категория, затем автор контента.
ROLE_ORDER: tuple[str, ...] = ("author", "category", "group", "rule_id")

#: Разделители, которые встречаются в именах правил SIEM-контента.
SEPARATORS: tuple[str, ...] = ("_", "-", ".")

#: Разбиение бесполезно, если групп меньше двух или почти столько же,
#: сколько правил: в обоих случаях группировка ничего не даёт.
MIN_GROUPS = 2
MAX_GROUP_RATIO = 0.9

EXAMPLES_PER_SEGMENT = 4


class SegmentStat(BaseModel):
    """Статистика одной позиции имени."""

    position: int
    role: str | None = None
    coverage: int
    distinct: int
    numeric_share: float
    examples: list[str] = Field(default_factory=list)


class NameScheme(BaseModel):
    """Кандидат разбиения имён на структурный код и описание."""

    separator: str
    segments: list[str]
    total: int
    coverage: int
    group_count: int
    stats: list[SegmentStat] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def depth(self) -> int:
        """Сколько ведущих позиций считаются структурным кодом."""
        return len(self.segments)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def score(self) -> float:
        """Насколько разбиение пригодно как каталог.

        Хорошее разбиение покрывает почти все правила и даёт число групп,
        далёкое и от единицы, и от числа правил.
        """
        if not self.total or self.group_count < MIN_GROUPS:
            return 0.0
        coverage_share = self.coverage / self.total
        group_share = self.group_count / self.total
        if group_share > MAX_GROUP_RATIO:
            return 0.0
        # Оптимум около десяти правил на группу; штраф растёт в обе стороны.
        balance = 1.0 - abs(group_share - 0.1) / 0.9
        return round(coverage_share * max(balance, 0.0), 4)


def _numeric_share(values: list[str]) -> float:
    if not values:
        return 0.0
    return round(sum(1 for v in values if v.isdigit()) / len(values), 4)


def _segment_stats(names: list[str], separator: str) -> list[SegmentStat]:
    split = [n.split(separator) for n in names]
    width = max((len(parts) for parts in split), default=0)
    stats: list[SegmentStat] = []
    for position in range(width):
        values = [parts[position] for parts in split if len(parts) > position]
        counter = Counter(values)
        stats.append(
            SegmentStat(
                position=position,
                coverage=len(values),
                distinct=len(counter),
                numeric_share=_numeric_share(values),
                examples=[v for v, _ in counter.most_common(EXAMPLES_PER_SEGMENT)],
            )
        )
    return stats


def _full_width(stats: list[SegmentStat], total: int) -> int:
    """Сколько ведущих позиций есть у всех имён без исключения.

    Дальше этой границы код точно не простирается: описание бывает разной
    длины, а код одинаковой. Внутри границы глубину выбирает `_best_depth`.
    """
    width = 0
    for stat in stats:
        if stat.coverage != total:
            break
        width += 1
        if width == len(ROLE_ORDER):
            break
    return width


def _roles_for(depth: int) -> list[str]:
    """Роли назначаются справа налево: последняя позиция — номер правила."""
    return list(ROLE_ORDER[len(ROLE_ORDER) - depth :])


def group_key_of(name: str, scheme: NameScheme) -> tuple[str, ...] | None:
    """Ключ группы правила: структурный код без номера самого правила.

    Возвращает None, если имя не разбирается схемой — такое правило
    становится группой само себе, а не попадает в общее ведро.
    """
    parts = name.split(scheme.separator)
    if len(parts) < scheme.depth:
        return None
    return tuple(parts[: scheme.depth - 1]) if scheme.depth > 1 else tuple(parts[:1])


def apply_scheme(name: str, scheme: NameScheme | None) -> RuleCode | None:
    """Структурный код правила по схеме. None, если имя схемой не разбирается."""
    if scheme is None:
        return None
    parts = name.split(scheme.separator)
    if len(parts) < scheme.depth:
        return None
    return RuleCode(**dict(zip(scheme.segments, parts, strict=False)))


def detect_name_schemes(names: list[str], limit: int = 3) -> list[NameScheme]:
    """Кандидаты схем именования, лучший первым.

    Пустой список означает, что структуры в именах нет — тогда каждое
    правило само себе группа, и это честный ответ, а не отказ.
    """
    total = len(names)
    if not total:
        return []

    candidates: list[NameScheme] = []
    for separator in SEPARATORS:
        if not any(separator in n for n in names):
            continue
        best = _best_scheme(names, separator, total)
        if best is not None:
            candidates.append(best)

    return sorted(candidates, key=lambda s: -s.score)[:limit]


def _build(names: list[str], separator: str, total: int, depth: int) -> NameScheme:
    stats = _segment_stats(names, separator)
    roles = _roles_for(depth)
    for stat, role in zip(stats[:depth], roles, strict=True):
        stat.role = role
    scheme = NameScheme(
        separator=separator,
        segments=roles,
        total=total,
        coverage=sum(1 for n in names if len(n.split(separator)) >= depth),
        group_count=0,
        stats=stats[: depth + 1],
    )
    keys = {group_key_of(n, scheme) for n in names}
    scheme.group_count = len({k for k in keys if k is not None})
    return scheme


def _best_scheme(names: list[str], separator: str, total: int) -> NameScheme | None:
    """Самое дробное разбиение, которое ещё остаётся каталогом.

    Из двух годных разбиений выбирается более глубокое: группа — это
    единица привязки к ATT&CK, и крупная группа заставляет натягивать одну
    технику на разнородные правила, тогда как мелкая просто требует больше
    разметки. Ошибка в сторону дробности дешевле.

    Отбраковываются вырожденные концы: одна группа на всю выгрузку и
    отдельная группа почти на каждое правило. Именно так отсеивается
    хвостовой свободный текст в именах одинаковой длины — он даёт почти
    уникальные ключи.
    """
    width = _full_width(_segment_stats(names, separator), total)
    for depth in range(width, MIN_GROUPS - 1, -1):
        scheme = _build(names, separator, total, depth)
        if scheme.score > 0:
            return scheme
    return None
