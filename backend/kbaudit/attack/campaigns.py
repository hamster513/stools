"""Кампании ATT&CK как цепочки шагов и наши пробелы в них.

Кампания — это то, что уже случилось: у неё есть имя, даты и набор техник.
Отсюда и польза: пробел в покрытии, попавший на шаг реальной кампании,
весит больше, чем пробел вообще.

Порядок техник ATT&CK не хранит, и выдумывать его нельзя. Цепочка
выстраивается по порядку тактик — он задан матрицей MITRE и означает
последовательность шагов атаки, от разведки к воздействию.
"""
from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

CAMPAIGNS = Path(__file__).with_name("attack_campaigns.json")


class Campaign(BaseModel):
    id: str
    name: str
    first_seen: str | None = None
    last_seen: str | None = None
    techniques: list[str] = Field(default_factory=list)


class Step(BaseModel):
    """Шаг цепочки — одна тактика и техники кампании в ней."""

    tactic: str
    techniques: list[str] = Field(default_factory=list)
    covered: list[str] = Field(default_factory=list)
    uncovered: list[str] = Field(default_factory=list)
    #: Шаг вне поля зрения сенсоров: разведка и подготовка ресурсов
    #: происходят вне периметра, правил на них не бывает.
    observable: bool = True

    @property
    def blind(self) -> bool:
        """Шаг, не закрытый ни одним правилом.

        Отличается от «закрыт частично» качественно: там, где закрыта
        хоть одна техника, у аналитика есть шанс заметить активность;
        здесь шаг проходит целиком мимо.

        Ненаблюдаемый шаг слепым не считается: требовать правил на то,
        что происходит у чужого регистратора доменов, значит выдумывать
        работу и топить настоящие пробелы в ней.
        """
        return self.observable and not self.covered


class Chain(BaseModel):
    """Кампания, разложенная по шагам, с нашими пробелами."""

    id: str
    name: str
    first_seen: str | None = None
    last_seen: str | None = None
    steps: list[Step] = Field(default_factory=list)
    technique_count: int = 0
    uncovered_count: int = 0

    @property
    def blind_steps(self) -> int:
        return sum(1 for s in self.steps if s.blind)


def load(path: Path = CAMPAIGNS) -> list[Campaign]:
    """Прочитать пак кампаний.

    Отсутствие файла не ошибка: без него продукт работает, просто
    не показывает цепочки.
    """
    if not path.is_file():
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [Campaign.model_validate(c) for c in raw.get("campaigns") or []]


def _is_covered(technique_id: str, ours: set[str]) -> bool:
    """Закрыта ли техника кампании нашей разметкой.

    Точное совпадение либо разметка родителем: назвав `T1059`, человек
    заявил семейство целиком. А вот разметка соседней подтехникой
    покрытием не считается: `T1059.003` не ловит `T1059.001`, и
    засчитывать одно за другое значит повторять ровно ту ошибку,
    ради которой заводились подтехники в карточке техники.
    """
    if technique_id in ours:
        return True
    parent = technique_id.split(".")[0]
    return parent != technique_id and parent in ours


def chains(
    campaigns: list[Campaign],
    tactics_of: dict[str, list[str]],
    tactic_order: list[str],
    ours: set[str],
    unobservable: frozenset[str] = frozenset(),
) -> list[Chain]:
    """Разложить кампании по шагам и отметить пробелы.

    Сортировка — по числу непокрытых шагов, потом по свежести: цепочка,
    в которой мы слепы на пяти шагах из восьми, важнее той, где на одном.
    """
    order = {name: index for index, name in enumerate(tactic_order)}
    out: list[Chain] = []
    for campaign in campaigns:
        buckets: dict[str, Step] = {}
        uncovered = 0
        for technique_id in campaign.techniques:
            covered = _is_covered(technique_id, ours)
            if not covered:
                uncovered += 1
            for tactic in tactics_of.get(technique_id, []):
                step = buckets.setdefault(
                    tactic, Step(tactic=tactic, observable=tactic not in unobservable)
                )
                step.techniques.append(technique_id)
                (step.covered if covered else step.uncovered).append(technique_id)
        steps = sorted(buckets.values(), key=lambda s: order.get(s.tactic, len(order)))
        if not steps:
            continue
        out.append(
            Chain(
                id=campaign.id,
                name=campaign.name,
                first_seen=campaign.first_seen,
                last_seen=campaign.last_seen,
                steps=steps,
                technique_count=len(campaign.techniques),
                uncovered_count=uncovered,
            )
        )
    out.sort(key=lambda c: (c.blind_steps, c.uncovered_count, c.last_seen or ""), reverse=True)
    return out
