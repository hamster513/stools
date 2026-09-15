"""Поиск правил-клонов.

Две копии логики с разными whitelist'ами неизбежно расходятся: в выгрузке
рядом лежат Default_Account_Usage и его форк _sidorov (ТЗ §4.2).
"""
from __future__ import annotations

from collections import Counter
from itertools import combinations

from kbaudit.models import ClonePair, Rule

DEFAULT_THRESHOLD = 0.8

#: Максимальная document frequency токена, при которой он считается редким.
#:
#: Жаккара самого по себе недостаточно: два разных детекта на общем словаре
#: событий (например, оба реагируют на один и тот же msgid антивируса или
#: ссылаются на один и тот же общий фильтр) дают похожесть вплоть до 1.0,
#: не будучи форком одной логики — это совпадение по словарю, а не копия.
#: Общий редкий токен — то, что действительно отличает форк от такого
#: совпадения: если пара делит что-то, что почти нигде больше в выгрузке
#: не встречается, это сильный сигнал копипасты, а не двух независимых
#: правил на одном семействе событий.
RARE_TOKEN_MAX_DF = 4


def signature(rule: Rule) -> frozenset[str]:
    """Объединение msgid, полей таксономии и ссылок на фильтры.

    Префиксы нужны, чтобы msgid "4688" и поле с тем же текстом не слиплись.
    """
    return frozenset(
        [f"msgid:{m}" for m in rule.msgids]
        + [f"field:{f}" for f in rule.taxonomy_fields]
        + [f"filter:{f}" for f in rule.filter_refs]
    )


def _jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def _document_frequency(signatures: dict[str, frozenset[str]]) -> Counter[str]:
    """Сколько правил из переданного списка содержат каждый токен сигнатуры.

    Считается по всей выгрузке (по всем сигнатурам разом), а не по паре —
    иначе "редкость" токена была бы артефактом того, с кем его сравнивают.
    """
    df: Counter[str] = Counter()
    for sig in signatures.values():
        df.update(sig)
    return df


def find_clones(
    rules: list[Rule],
    threshold: float = DEFAULT_THRESHOLD,
    rare_token_max_df: int = RARE_TOKEN_MAX_DF,
) -> list[ClonePair]:
    """Пары правил с похожестью не ниже threshold, у которых вдобавок есть
    хотя бы один общий редкий токен (document frequency <= rare_token_max_df).

    Без этого условия высокий Жаккар ловит не только форки, но и разные
    правила на общем словаре событий — см. докстроку RARE_TOKEN_MAX_DF.
    """
    signatures = {r.name: signature(r) for r in rules if signature(r)}
    df = _document_frequency(signatures)
    pairs = []
    for a, b in combinations(sorted(signatures), 2):
        score = _jaccard(signatures[a], signatures[b])
        if score < threshold:
            continue
        common = signatures[a] & signatures[b]
        if not any(df[token] <= rare_token_max_df for token in common):
            continue
        pairs.append(ClonePair(rule_a=a, rule_b=b, similarity=round(score, 4)))
    return sorted(pairs, key=lambda p: (-p.similarity, p.rule_a, p.rule_b))
