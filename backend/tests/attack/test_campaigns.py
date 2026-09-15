"""Цепочки кампаний и наши пробелы в них."""
from __future__ import annotations

import json

from kbaudit.attack.bundle import load_default
from kbaudit.attack.campaigns import CAMPAIGNS, Campaign, chains, load

_TACTICS = {
    "T1566": ["initial-access"],
    "T1059": ["execution"],
    "T1059.001": ["execution"],
    "T1059.003": ["execution"],
    "T1486": ["impact"],
    "T1583.001": ["resource-development"],
}
_ORDER = ["resource-development", "initial-access", "execution", "impact"]


def _one(techniques: list[str]) -> list[Campaign]:
    return [Campaign(id="C0001", name="Проверка", last_seen="2024-01-01", techniques=techniques)]


def test_steps_follow_the_matrix_order_not_the_data_order() -> None:
    """Порядок шагов задан матрицей MITRE и означает ход атаки.

    В самих данных порядка нет, и выдумывать его нельзя — но и выдавать
    алфавитный за последовательность шагов тоже.
    """
    chain = chains(_one(["T1486", "T1566", "T1059"]), _TACTICS, _ORDER, set())[0]
    assert [s.tactic for s in chain.steps] == ["initial-access", "execution", "impact"]


def test_parent_markup_covers_the_subtechnique_but_a_sibling_does_not() -> None:
    """Назвав `T1059`, человек заявил семейство. Назвав `T1059.003` — нет.

    Засчитывать соседнюю подтехнику за покрытие значит повторять ровно
    ту ошибку, ради которой заводились подтехники в карточке техники:
    `cmd.exe` не ловит PowerShell.
    """
    covered = chains(_one(["T1059.001"]), _TACTICS, _ORDER, {"T1059"})[0]
    assert covered.uncovered_count == 0

    sibling = chains(_one(["T1059.001"]), _TACTICS, _ORDER, {"T1059.003"})[0]
    assert sibling.uncovered_count == 1
    assert sibling.blind_steps == 1


def test_unobservable_steps_are_not_counted_as_blind() -> None:
    """Разведку и подготовку ресурсов сенсоры не видят по определению.

    Считать их слепыми шагами значит требовать правил, которых не бывает,
    и топить настоящие пробелы в выдуманной работе.
    """
    without = chains(_one(["T1583.001", "T1566"]), _TACTICS, _ORDER, set())[0]
    assert without.blind_steps == 2

    with_filter = chains(
        _one(["T1583.001", "T1566"]),
        _TACTICS,
        _ORDER,
        set(),
        unobservable=frozenset({"resource-development"}),
    )[0]
    assert with_filter.blind_steps == 1
    assert [s.tactic for s in with_filter.steps if not s.observable] == ["resource-development"]


def test_chains_are_ordered_by_how_blind_we_are() -> None:
    """Цепочка, где мы слепы на пяти шагах, важнее той, где на одном."""
    many = Campaign(id="C1", name="Слепая", last_seen="2020-01-01", techniques=["T1566", "T1059", "T1486"])
    few = Campaign(id="C2", name="Закрытая", last_seen="2025-01-01", techniques=["T1566", "T1059"])
    result = chains([few, many], _TACTICS, _ORDER, {"T1566", "T1059"})
    assert [c.id for c in result] == ["C1", "C2"]


def test_shipped_pack_holds_real_campaigns_with_dates() -> None:
    """Пак вложен в образ и говорит о действующей матрице.

    Кампании отстают: самая свежая датирована концом 2025 года. Это надо
    знать, а не обнаруживать на экране как оперативные данные.
    """
    campaigns = load()
    assert len(campaigns) > 40
    assert all(len(c.techniques) >= 3 for c in campaigns), "две техники — не цепочка"

    live = {t.technique_id for t in load_default().techniques}
    unknown = {t for c in campaigns for t in c.techniques} - live
    assert not unknown, f"чужие идентификаторы: {sorted(unknown)[:5]}"

    raw = json.loads(CAMPAIGNS.read_text(encoding="utf-8"))
    dated = [c for c in raw["campaigns"] if c.get("last_seen")]
    assert len(dated) > 40
