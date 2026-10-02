"""Маркировка правил: на что оператору смотреть в первую очередь.

Живёт отдельно, потому что нужна в трёх местах сразу: в инвентаре правил,
в карточке техники и в карточке группы. Правило с открытыми находками
должно выглядеть одинаково тревожно, откуда бы на него ни смотрели.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from api.db.models import Finding as FindingRow
from api.db.models import RuleRow
from api.modules.siem.findings_adapter import MODULE, SCOPE, finding_key, key_salt
from api.platform.findings import service as finding_svc

#: Порядок тяжести, от большего к меньшему.
SEVERITY_ORDER = ("high", "medium", "low")


def group_key(row: RuleRow) -> str:
    """Ключ группы правила — код без номера самого правила.

    Совпадает с `RuleCode.group_key` ядра; здесь собирается из колонок,
    потому что разобранный код в базе разложен по трём полям.
    """
    return "/".join(p for p in (row.author, row.type_id_cat, row.type_id_group) if p)


def attention_by_rule(db: Session, snapshot_id: int) -> dict[str, tuple[int, str | None]]:
    """Учитываемые находки и их наибольшая тяжесть по каждому правилу.

    Статусы — общие статусы находок платформы, вне снапшотов, по ключу
    находки (object_uuid, kind, field, значение), а не по её идентификатору:
    принятое решение обязано пережить загрузку новой выгрузки. Какие статусы
    учитываются, задаёт настройка платформы `counted` (по умолчанию не
    учитываются «Принят риск», «Ложное срабатывание», «Устранена»).
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
    salt = key_salt(db)
    states = finding_svc.state_map(db, MODULE, SCOPE)
    counted = finding_svc.counted_statuses(db)

    out: dict[str, tuple[int, str | None]] = {}
    for object_uuid, kind, field, value_hash, severity in findings:
        if not finding_svc.is_counted(states.get(finding_key(salt, object_uuid, kind, field, value_hash)), counted):
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
