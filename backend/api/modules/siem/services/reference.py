"""Эталонная разметка: загрузка, сопоставление с правилами и сверка.

Эталон — чужая таблица «правило → техника», сделанная руками аналитиков.
Продукт её не правит и ею не подменяет свою разметку: это мнение, с которым
сверяются. Ценность в разнице, а не в самом списке.
"""
from __future__ import annotations

import datetime as dt
import json

from sqlalchemy.orm import Session

from api.db.models import AttackMarkup, AttackReference, RuleRow
from api.modules.attack.services.attack_bundle import current as current_bundle
from api.modules.siem.services.attack import (
    SOURCE_REFERENCE,
    STATUS_CONFIRMED,
    MarkupTechnique,
    markup_by_rule,
    techniques_of,
)
from api.modules.siem.services.rule_attention import group_key
from kbaudit.attack.prevalence import load_revoked, migrate
from kbaudit.attack.reference import ParsedReference, code_key

#: Как совпало правило эталона с правилом выгрузки. Порядок — от точного
#: к приблизительному; в отчёте видно, чем именно пришлось воспользоваться.
MATCH_NAME = "name"
MATCH_UUID = "uuid"
MATCH_CODE = "code"

#: Итог сверки по одному правилу.
VERDICT_SAME = "same"
VERDICT_FINER = "reference_finer"
VERDICT_COARSER = "reference_coarser"
VERDICT_PARTIAL = "partial"
VERDICT_DIFFERENT = "different"
VERDICT_NO_MARKUP = "no_markup"


def _index(rules: list[RuleRow]) -> tuple[dict[str, RuleRow], dict[str, RuleRow], dict[str, list[RuleRow]]]:
    by_name = {r.name.upper(): r for r in rules}
    by_uuid = {r.uuid: r for r in rules}
    by_code: dict[str, list[RuleRow]] = {}
    for rule in rules:
        key = code_key(rule.name)
        if key:
            by_code.setdefault(key, []).append(rule)
    return by_name, by_uuid, by_code


def _match(
    key: str,
    by_name: dict[str, RuleRow],
    by_uuid: dict[str, RuleRow],
    by_code: dict[str, list[RuleRow]],
) -> tuple[list[RuleRow], str | None]:
    """Правила выгрузки, которым соответствует строка эталона.

    По коду совпадений может быть несколько: код не уникален — в выгрузке
    заказчика на 187 правил приходится 14 совпадающих (копии и
    переименования). Эталон в таком случае относится ко всем: человек
    размечал приём, а не конкретную копию правила.
    """
    exact = by_name.get(key.upper())
    if exact is not None:
        return [exact], MATCH_NAME
    if key in by_uuid:
        return [by_uuid[key]], MATCH_UUID
    found = by_code.get(code_key(key))
    if found:
        return list(found), MATCH_CODE
    return [], None


def import_reference(
    db: Session, parsed: ParsedReference, snapshot_id: int, source: str, login: str | None
) -> dict[str, object]:
    """Заменить эталон содержимым разобранной таблицы.

    Заменить, а не дополнить: эталон — это один документ целиком. Слияние
    двух версий таблицы дало бы разметку, которой нет ни в одной из них.
    """
    rules = db.query(RuleRow).filter(RuleRow.snapshot_id == snapshot_id).all()
    by_name, by_uuid, by_code = _index(rules)
    live = {t.technique_id for t in current_bundle(db).techniques}
    replaced = load_revoked()

    db.query(AttackReference).delete()
    now = dt.datetime.now(dt.UTC)
    matched = 0
    unmatched: list[str] = []
    by_strategy: dict[str, int] = {}
    moved = 0
    unknown: set[str] = set()

    for row in parsed.rows:
        migrated: list[str] = []
        for technique in row.techniques:
            resolved = migrate(technique, replaced, live)
            if resolved is None:
                unknown.add(technique)
                continue
            if resolved != technique:
                moved += 1
            migrated.append(resolved)

        targets, strategy = _match(row.key, by_name, by_uuid, by_code)
        if not targets:
            unmatched.append(row.key)
            db.add(
                AttackReference(
                    rule_uuid=None,
                    source_key=row.key,
                    techniques_json=json.dumps(sorted(set(migrated))),
                    original_json=json.dumps(row.techniques),
                    note=row.note or None,
                    source=source,
                    imported_by=login,
                    imported_at=now,
                )
            )
            continue
        by_strategy[strategy or "?"] = by_strategy.get(strategy or "?", 0) + 1
        for rule in targets:
            matched += 1
            db.add(
                AttackReference(
                    rule_uuid=rule.uuid,
                    source_key=row.key,
                    techniques_json=json.dumps(sorted(set(migrated))),
                    original_json=json.dumps(row.techniques),
                    note=row.note or None,
                    source=source,
                    imported_by=login,
                    imported_at=now,
                )
            )
    db.commit()

    covered = {r.rule_uuid for r in db.query(AttackReference) if r.rule_uuid}
    return {
        "source": source,
        "rows": len(parsed.rows),
        "rows_without_techniques": parsed.without_techniques,
        "matched_rules": matched,
        "matched_by": by_strategy,
        "unmatched_keys": sorted(unmatched),
        # Правила выгрузки, которых нет в эталоне: разметку по ним сверить
        # не с чем, и это тоже надо показать, а не умолчать.
        "rules_without_reference": len(rules) - len(covered),
        # Ссылки на техники, отозванные MITRE и перенесённые на замену.
        "migrated_techniques": moved,
        "unknown_techniques": sorted(unknown),
        "columns": parsed.columns,
    }


def _verdict(ours: set[str], theirs: set[str]) -> str:
    if not ours:
        return VERDICT_NO_MARKUP
    if ours == theirs:
        return VERDICT_SAME
    our_parents = {t.split(".")[0] for t in ours}
    their_parents = {t.split(".")[0] for t in theirs}
    if our_parents == their_parents:
        # Семейство то же, различается лишь глубина: кто-то назвал
        # подтехнику, кто-то остановился на технике. Это не спор.
        if all("." not in t for t in ours) and any("." in t for t in theirs):
            return VERDICT_FINER
        if any("." in t for t in ours) and all("." not in t for t in theirs):
            return VERDICT_COARSER
    if our_parents & their_parents:
        return VERDICT_PARTIAL
    return VERDICT_DIFFERENT


def compare(db: Session, snapshot_id: int) -> dict[str, object]:
    """Сверка нашей разметки с эталоном по каждому правилу."""
    reference: dict[str, AttackReference] = {
        row.rule_uuid: row for row in db.query(AttackReference) if row.rule_uuid
    }
    markup = markup_by_rule(db)
    rules = db.query(RuleRow).filter(RuleRow.snapshot_id == snapshot_id).all()

    counts: dict[str, int] = {}
    items: list[dict[str, object]] = []
    for rule in sorted(rules, key=lambda r: r.name):
        row = reference.get(rule.uuid)
        if row is None:
            continue
        theirs = set(json.loads(row.techniques_json or "[]"))
        markup_row = markup.get(rule.uuid)
        ours = {t.technique_id for t in techniques_of(markup_row)} if markup_row else set()
        verdict = _verdict(ours, theirs)
        counts[verdict] = counts.get(verdict, 0) + 1
        items.append(
            {
                "uuid": rule.uuid,
                "name": rule.name,
                "source_key": row.source_key,
                "verdict": verdict,
                "ours": sorted(ours),
                "theirs": sorted(theirs),
                "original": sorted(set(json.loads(row.original_json or "[]"))),
                "note": row.note or "",
                "status": markup_row.status if markup_row else "unmapped",
                "inherited": bool(markup_row.inherited) if markup_row else False,
            }
        )

    orphans = [
        {"source_key": row.source_key, "theirs": sorted(set(json.loads(row.techniques_json or "[]")))}
        for row in db.query(AttackReference)
        if not row.rule_uuid
    ]
    any_row = db.query(AttackReference).first()
    return {
        "loaded": any_row is not None,
        "source": any_row.source if any_row else None,
        "imported_at": any_row.imported_at.isoformat() if any_row else None,
        "imported_by": any_row.imported_by if any_row else None,
        "compared": len(items),
        "counts": counts,
        "items": items,
        "unmatched": sorted(orphans, key=lambda o: o["source_key"]),
        "rules_without_reference": sum(1 for r in rules if r.uuid not in reference),
    }


def apply_reference(
    db: Session,
    snapshot_id: int,
    login: str | None,
    rule_uuid: str | None = None,
    verdicts: list[str] | None = None,
) -> dict[str, object]:
    """Принять эталон как разметку — по одному правилу или пачкой.

    Записывается с источником `reference`, а не `manual`: решение принимал
    человек, но в чужом документе, и через полгода это единственный способ
    вспомнить, откуда у правила взялась именно эта техника.

    Статус — «подтверждено»: это работа человека, а не догадка модели.
    Следствие важное: последующие прогоны модели такую разметку не трогают,
    и принятый эталон не будет затёрт при следующем «разметить моделью».

    Правила, по которым эталон молчит, не трогаются вовсе. Пустой эталон —
    это отсутствие мнения, а не мнение «техник нет».
    """
    current = compare(db, snapshot_id)
    items = [i for i in current["items"] if isinstance(i, dict)]
    if rule_uuid is not None:
        items = [i for i in items if i["uuid"] == rule_uuid]
    if verdicts:
        items = [i for i in items if i["verdict"] in verdicts]

    reference = {row.rule_uuid: row for row in db.query(AttackReference) if row.rule_uuid}
    now = dt.datetime.now(dt.UTC)
    version = current_bundle(db).version
    applied = 0
    skipped_empty = 0

    for item in items:
        row = reference.get(str(item["uuid"]))
        if row is None:
            continue
        techniques = sorted(set(json.loads(row.techniques_json or "[]")))
        if not techniques:
            skipped_empty += 1
            continue
        markup = (
            db.query(AttackMarkup)
            .filter(AttackMarkup.rule_uuid == item["uuid"])
            .one_or_none()
        )
        if markup is None:
            markup = AttackMarkup(rule_uuid=str(item["uuid"]))
            db.add(markup)
        rule = db.query(RuleRow).filter(RuleRow.uuid == item["uuid"]).first()
        if rule is not None:
            markup.group_name = group_key(rule)
        markup.techniques_json = json.dumps(
            [
                MarkupTechnique(
                    technique_id=technique,
                    confidence="высокая",
                    evidence=f"Принято из эталона {row.source or 'таблицы'}"
                    + (f": {row.note}" if row.note else ""),
                    source=SOURCE_REFERENCE,
                ).model_dump()
                for technique in techniques
            ],
            ensure_ascii=False,
        )
        markup.status = STATUS_CONFIRMED
        # Разметка теперь относится к этому правилу, а не к его группе.
        markup.inherited = False
        markup.reviewed_by = login
        markup.reviewed_at = now
        markup.reason = f"Эталон {row.source or ''}".strip()
        markup.attack_version = markup.attack_version or version
        applied += 1

    db.commit()
    return {"applied": applied, "skipped_empty": skipped_empty, "considered": len(items)}
