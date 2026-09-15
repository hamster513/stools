"""Сравнение пары правил-клонов.

Клоны находятся по сигнатуре (msgid, поля таксономии, ссылки на фильтры),
поэтому первое, что аналитику нужно увидеть, — чем сигнатуры расходятся.
Тело сравнивается построчно стандартным difflib и отдаётся уже выровненным
для показа бок о бок: фронту остаётся только раскрасить строки.
"""
from __future__ import annotations

import difflib
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from api.db.models import ClonePairRow, RuleField, RuleFilterRef, RuleMsgid, RuleRow


def _rule(db: Session, snapshot_id: int, name: str) -> RuleRow:
    rule = (
        db.query(RuleRow)
        .filter(RuleRow.snapshot_id == snapshot_id, RuleRow.name == name)
        .order_by(RuleRow.id)
        .first()
    )
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"правило {name} не найдено")
    return rule


def _side(db: Session, rule: RuleRow) -> dict[str, Any]:
    msgids = {
        m.msgid
        for m in db.query(RuleMsgid).filter(
            RuleMsgid.snapshot_id == rule.snapshot_id, RuleMsgid.rule_uuid == rule.uuid
        )
    }
    fields = {
        f.field
        for f in db.query(RuleField).filter(
            RuleField.snapshot_id == rule.snapshot_id, RuleField.rule_uuid == rule.uuid
        )
    }
    filters = {
        f.filter_name
        for f in db.query(RuleFilterRef).filter(
            RuleFilterRef.snapshot_id == rule.snapshot_id, RuleFilterRef.rule_uuid == rule.uuid
        )
    }
    return {
        "uuid": rule.uuid,
        "name": rule.name,
        "title": rule.title_ru or rule.title_en,
        "body": rule.body_text,
        "_sets": {"msgids": msgids, "fields": fields, "filters": filters},
    }


def _split(a: set[str], b: set[str]) -> dict[str, list[str]]:
    return {"common": sorted(a & b), "only_a": sorted(a - b), "only_b": sorted(b - a)}


def _lines(text: str | None) -> list[str]:
    return text.splitlines() if text else []


def align(body_a: str | None, body_b: str | None) -> list[dict[str, Any]]:
    """Построчная выкладка двух тел: замена идёт парами строк, хвост
    длинной стороны — вставками или удалениями с пустой ячейкой напротив."""
    a, b = _lines(body_a), _lines(body_b)
    out: list[dict[str, Any]] = []
    matcher = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            out.extend({"kind": "equal", "a": a[i], "b": b[j1 + k]} for k, i in enumerate(range(i1, i2)))
            continue
        left, right = a[i1:i2], b[j1:j2]
        for k in range(max(len(left), len(right))):
            la = left[k] if k < len(left) else None
            lb = right[k] if k < len(right) else None
            kind = "replace" if la is not None and lb is not None else "delete" if lb is None else "insert"
            out.append({"kind": kind, "a": la, "b": lb})
    return out


def compare(db: Session, snapshot_id: int, rule_a: str, rule_b: str) -> dict[str, Any]:
    left = _side(db, _rule(db, snapshot_id, rule_a))
    right = _side(db, _rule(db, snapshot_id, rule_b))
    pair = (
        db.query(ClonePairRow)
        .filter(
            ClonePairRow.snapshot_id == snapshot_id,
            ((ClonePairRow.rule_a == rule_a) & (ClonePairRow.rule_b == rule_b))
            | ((ClonePairRow.rule_a == rule_b) & (ClonePairRow.rule_b == rule_a)),
        )
        .first()
    )
    lines = align(left["body"], right["body"])
    sets_a, sets_b = left.pop("_sets"), right.pop("_sets")
    return {
        "a": left,
        "b": right,
        # Пара может и не быть клоном в таблице: сравнить можно любые два
        # правила по прямой ссылке. Тогда похожести нет.
        "similarity": pair.similarity if pair is not None else None,
        "signature": {key: _split(sets_a[key], sets_b[key]) for key in ("msgids", "fields", "filters")},
        "lines": lines,
        "changed_lines": sum(1 for line in lines if line["kind"] != "equal"),
    }
