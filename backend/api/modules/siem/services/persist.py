"""Раскладка результата ядра (`ParsedArchive` + `AuditReport`) по таблицам.

Используется и при первичной загрузке (api/services/ingest.py), и при
пересчёте после смены профиля (PUT /api/profile) — во втором случае
разбор архива не повторяется: `ParsedArchive` берётся из JSON-кэша рядом
с архивом (контракт: «Разбор архива при этом не повторяется»), а
пересобирается только `AuditReport`.

Функция идемпотентна: старые строки снапшота удаляются и вставляются заново
одной транзакцией — так `PUT /api/profile` не плодит дубликаты и не требует
отдельной ветки «обновить, а не вставить» для каждой таблицы.
"""
from __future__ import annotations

import json
from collections import Counter

from sqlalchemy import delete
from sqlalchemy.orm import Session

from api.db.models import (
    ClonePairRow,
    DivergenceRow,
    RuleDependency,
    RuleField,
    RuleFilterRef,
    RuleMsgid,
    RuleRow,
    RuleTableRef,
    Snapshot,
    TableListRow,
)
from api.db.models import (
    Finding as FindingRow,
)
from api.security import hash_value
from kbaudit.analyzers.dependencies import build_edges, inherited_msgids
from kbaudit.models import ObjectType, ParsedArchive
from kbaudit.report import AuditReport

_CHILD_TABLES = (
    RuleMsgid,
    RuleField,
    RuleTableRef,
    RuleFilterRef,
    RuleDependency,
    TableListRow,
    FindingRow,
    ClonePairRow,
    DivergenceRow,
    RuleRow,
)


def _clear_snapshot_children(db: Session, snapshot_id: int) -> None:
    for model in _CHILD_TABLES:
        db.execute(delete(model).where(model.snapshot_id == snapshot_id))


def persist_report(
    db: Session, snapshot: Snapshot, parsed: ParsedArchive, report: AuditReport
) -> None:
    """Записывает разбор и анализ в БД, обновляя производные числа снапшота.

    Одна транзакция: либо весь снапшот согласован, либо (при исключении)
    ничего не закоммичено — вызывающий код (api/services/ingest.py) решает,
    что делать со снапшотом при сбое.
    """
    snapshot_id = snapshot.id
    _clear_snapshot_children(db, snapshot_id)

    bodies_by_uuid = {
        b.uuid: b for b in parsed.bodies if b.object_type == ObjectType.CORRELATION
    }

    edges = build_edges(report.rules)
    inherited = inherited_msgids(report.rules, edges)

    for rule in report.rules:
        code = rule.code
        db.add(
            RuleRow(
                snapshot_id=snapshot_id,
                uuid=rule.uuid,
                name=rule.name,
                object_id=rule.object_id,
                origin=rule.origin,
                body_type=rule.body_type,
                parse_status=str(rule.parse_status),
                type_id_cat=code.category if code else None,
                type_id_group=code.group if code else None,
                type_id_num=code.rule_id if code else None,
                author=code.author if code else None,
                body_hash=rule.body_hash,
                title_ru=rule.title_ru,
                description_ru="\n".join(rule.descriptions_ru) or None,
                description_en="\n".join(rule.descriptions_en) or None,
                title_en=rule.title_en,
                # Пересчитывается ниже, вторым проходом: is_scoped_by зависит
                # от списка scoping-таблиц профиля, а тот известен только
                # из report.table_ranking (is_scoping выставлен там).
                scoped_by_list=False,
                body_text=(
                    bodies_by_uuid[rule.uuid].body_text
                    if rule.uuid in bodies_by_uuid
                    else None
                ),
            )
        )

        for msgid in rule.msgids:
            db.add(
                RuleMsgid(snapshot_id=snapshot_id, rule_uuid=rule.uuid, msgid=msgid, inherited=False)
            )
        for msgid in inherited.get(rule.name, set()) - set(rule.msgids):
            db.add(
                RuleMsgid(snapshot_id=snapshot_id, rule_uuid=rule.uuid, msgid=msgid, inherited=True)
            )
        for field in rule.taxonomy_fields:
            db.add(RuleField(snapshot_id=snapshot_id, rule_uuid=rule.uuid, field=field))
        for table in rule.table_reads:
            db.add(
                RuleTableRef(
                    snapshot_id=snapshot_id, rule_uuid=rule.uuid, table_name=table, direction="read"
                )
            )
        for table in rule.table_writes:
            db.add(
                RuleTableRef(
                    snapshot_id=snapshot_id, rule_uuid=rule.uuid, table_name=table, direction="write"
                )
            )
        for filt in rule.filter_refs:
            db.add(RuleFilterRef(snapshot_id=snapshot_id, rule_uuid=rule.uuid, filter_name=filt))

    for edge in edges:
        db.add(RuleDependency(snapshot_id=snapshot_id, parent=edge.parent, child=edge.child))

    for table_list in parsed.table_lists:
        db.add(
            TableListRow(
                snapshot_id=snapshot_id, name=table_list.name, value_count=table_list.value_count
            )
        )

    for finding in report.findings:
        db.add(
            FindingRow(
                snapshot_id=snapshot_id,
                object_type=str(finding.object_type),
                object_uuid=finding.object_uuid,
                object_name=finding.object_name,
                kind=finding.kind,
                severity=finding.severity,
                field=finding.field,
                value=finding.value,
                value_hash=hash_value(finding.value),
                polarity=str(finding.polarity),
                shape=finding.shape,
                in_table=finding.in_table,
                table_name=finding.table_name,
                body_excerpt=finding.body_excerpt,
            )
        )

    for clone in report.clones:
        db.add(
            ClonePairRow(
                snapshot_id=snapshot_id,
                rule_a=clone.rule_a,
                rule_b=clone.rule_b,
                similarity=clone.similarity,
            )
        )

    for div in report.divergences:
        db.add(
            DivergenceRow(
                snapshot_id=snapshot_id,
                value=div.value,
                field=div.field,
                table_name=div.table_name,
                hardcoded_in=div.hardcoded_in,
                affected_rules_json=json.dumps(div.affected_rules, ensure_ascii=False),
                blast_radius=div.blast_radius,
            )
        )

    authors = Counter(r.code.author for r in report.rules if r.code and r.code.author)

    snapshot.kb_version = parsed.taxonomy.version
    snapshot.taxonomy_version = parsed.taxonomy.version
    snapshot.rule_count = report.rule_count
    snapshot.group_count = report.group_count
    snapshot.rules_without_code = report.rules_without_code
    snapshot.unsupported_count = report.unsupported_count
    snapshot.edge_count = report.edge_count
    snapshot.scoped_count = report.scoped_count
    snapshot.finding_count = report.finding_count
    snapshot.findings_by_kind_json = json.dumps(report.findings_by_kind)
    snapshot.findings_by_polarity_json = json.dumps(report.findings_by_polarity, ensure_ascii=False)
    snapshot.findings_by_object_type_json = json.dumps(
        report.findings_by_object_type, ensure_ascii=False
    )
    snapshot.objects_with_findings = report.objects_with_findings
    snapshot.in_table_count = report.in_table_count
    snapshot.divergence_count = report.divergence_count
    snapshot.clone_count = report.clone_count
    snapshot.rules_without_msgid = report.rules_without_msgid
    snapshot.name_scheme_coverage = report.name_scheme_coverage
    snapshot.table_ranking_json = json.dumps(
        [t.model_dump(mode="json") for t in report.table_ranking], ensure_ascii=False
    )
    snapshot.authors_json = json.dumps(authors, ensure_ascii=False)
    snapshot.unresolved_json = json.dumps(report.unresolved, ensure_ascii=False)

    db.flush()

    # scoped_by_list зависит от профиля (какие списки считаются ограничивающими),
    # а Rule.is_scoped_by уже применён внутри report через scoped_count — здесь
    # проставляем его на каждую строку rule, используя тот же набор имён.
    scoping = set(_scoping_from_report(report))
    if scoping:
        rows = {r.uuid: r for r in db.query(RuleRow).filter(RuleRow.snapshot_id == snapshot_id)}
        for rule in report.rules:
            row = rows.get(rule.uuid)
            if row is not None:
                row.scoped_by_list = rule.is_scoped_by(scoping)


def _scoping_from_report(report: AuditReport) -> list[str]:
    """Имена ограничивающих списков, отмеченных в профиле этого прогона.

    AuditReport не хранит профиль целиком, но table_status помечен
    `is_scoping` только для списков, которые пришли из TableRoles.scoping,
    отмеченных человеком.
    """
    return [t.name for t in report.table_ranking if t.is_scoping]
