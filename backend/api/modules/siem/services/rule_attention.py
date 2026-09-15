"""Маркировка правил: на что оператору смотреть в первую очередь.

Живёт отдельно, потому что нужна в трёх местах сразу: в инвентаре правил,
в карточке техники и в карточке группы. Правило с открытыми находками
должно выглядеть одинаково тревожно, откуда бы на него ни смотрели.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from api.db.models import Finding as FindingRow
from api.db.models import FindingVerdict, RuleRow

#: Порядок тяжести, от большего к меньшему.
SEVERITY_ORDER = ("high", "medium", "low")


def group_key(row: RuleRow) -> str:
    """Ключ группы правила — код без номера самого правила.

    Совпадает с `RuleCode.group_key` ядра; здесь собирается из колонок,
    потому что разобранный код в базе разложен по трём полям.
    """
    return "/".join(p for p in (row.author, row.type_id_cat, row.type_id_group) if p)


def attention_by_rule(db: Session, snapshot_id: int) -> dict[str, tuple[int, str | None]]:
    """Открытые находки и их наибольшая тяжесть по каждому правилу.

    Вердикты живут вне снапшотов и соединяются с находками по ключу
    (object_uuid, kind, field, value_hash), а не по идентификатору находки:
    принятое решение обязано пережить загрузку новой выгрузки.
    """
    findings = (
        db.query(
            FindingRow.object_uuid,
            FindingRow.kind,
            FindingRow.field,
            FindingRow.value_hash,
            FindingRow.severity,
        )
        .filter(FindingRow.snapshot_id == snapshot_id)
        .all()
    )
    accepted = {
        (v.object_key, v.kind, v.field, v.value_hash)
        for v in db.query(FindingVerdict).filter(
            FindingVerdict.key_kind == "uuid", FindingVerdict.status == "accepted"
        )
    }

    out: dict[str, tuple[int, str | None]] = {}
    for object_uuid, kind, field, value_hash, severity in findings:
        if (object_uuid, kind, field, value_hash) in accepted:
            continue
        count, worst = out.get(object_uuid, (0, None))
        if worst is None or SEVERITY_ORDER.index(severity) < SEVERITY_ORDER.index(worst):
            worst = severity
        out[object_uuid] = (count + 1, worst)
    return out


def rules_of_group(db: Session, snapshot_id: int, group: str) -> list[dict[str, object]]:
    """Правила группы с маркировкой — то, что видно и в карточке техники,
    и в карточке группы."""
    attention = attention_by_rule(db, snapshot_id)
    rows = (
        db.query(RuleRow)
        .filter(RuleRow.snapshot_id == snapshot_id)
        .order_by(RuleRow.name)
        .all()
    )
    return [
        {
            "uuid": r.uuid,
            "name": r.name,
            "parse_status": r.parse_status,
            "scoped": r.scoped_by_list,
            "open_finding_count": attention.get(r.uuid, (0, None))[0],
            "max_severity": attention.get(r.uuid, (0, None))[1],
        }
        for r in rows
        if group_key(r) == group
    ]
