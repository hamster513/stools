"""Расхождение «правило ↔ табличный список».

Значение зашито в тело правила и одновременно лежит в списке. Это два
источника истины: правка списка не меняет поведение правила, и наоборот.
Активный источник ложных срабатываний и пропусков (ТЗ §4.1).
"""
from __future__ import annotations

from pydantic import BaseModel, Field, computed_field

from kbaudit.models import Finding, Rule

#: Класс 1 и только он: остальные классы к спискам отношения не имеют.
DUPLICATE_KIND = 1


class Divergence(BaseModel):
    value: str
    field: str
    table_name: str
    hardcoded_in: str
    affected_rules: list[str] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def blast_radius(self) -> int:
        """Сколько правил изменят поведение, если убрать значение из списка."""
        return len(self.affected_rules)


def find_divergences(findings: list[Finding], rules: list[Rule]) -> list[Divergence]:
    rows: list[Divergence] = []
    for finding in findings:
        if finding.kind != DUPLICATE_KIND or not finding.table_name:
            continue
        tables = {t.strip() for t in finding.table_name.split(",")}
        affected = sorted(
            rule.name for rule in rules if tables & set(rule.table_reads)
        )
        rows.append(
            Divergence(
                value=finding.value,
                field=finding.field,
                table_name=finding.table_name,
                hardcoded_in=finding.object_name,
                affected_rules=affected,
            )
        )
    return sorted(rows, key=lambda r: (-len(r.affected_rules), r.table_name, r.value))
