"""Правила: список с агрегатами, деталь с телом.

Тело правила — чувствительные данные (спека §10, контракт «Правила»):
отдаётся только `GET /rules/{uuid}`, никогда в списке.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session, defer

from api.db.base import get_db
from api.db.models import (
    AppUser,
    RuleDependency,
    RuleMsgid,
    RuleRow,
    RuleTableRef,
    TableListRow,
)
from api.db.models import Finding as FindingRow
from api.deps import get_current_user
from api.modules.attack.services.attack_bundle import current as current_bundle
from api.modules.siem.findings_adapter import MODULE, SCOPE, display_salt, key_of
from api.modules.siem.services.attack import (
    STATUS_CONFIRMED,
    STATUS_SUGGESTED,
    STATUS_UNMAPPED,
    markup_by_rule,
    techniques_of,
)
from api.modules.siem.services.highlight import spans_for
from api.modules.siem.services.kb_inventory import deployment_by_rule, rule_fields, set_names
from api.modules.siem.services.rule_attention import attention_by_rule, group_key
from api.platform.export import Column, export_response
from api.platform.findings import service as finding_svc

router = APIRouter(prefix="/rules", tags=["rules"])


class AttackTechniqueBrief(BaseModel):
    technique_id: str
    name_ru: str | None = None
    name: str
    tactics: list[str] = []
    confidence: str = ""
    evidence: str = ""
    source: str = ""


class RuleAttack(BaseModel):
    """Разметка правила по ATT&CK.

    По правилу, а не по группе: правила одной группы обнаруживают разные
    техники. На сверке с ручной разметкой заказчика из 32 групп лишь
    у 14 все правила сошлись на одной технике, а у `DEMO/HC/002`
    двадцать одно правило дало девятнадцать разных техник.
    """

    status: str = STATUS_UNMAPPED
    group: str | None = None
    techniques: list[AttackTechniqueBrief] = []
    #: Разметка досталась от группы и для этого правила не уточнялась.
    #: Показывать её как проверенную нельзя: она ничего не утверждает
    #: об этом правиле в отдельности.
    inherited: bool = False


class RuleListItem(BaseModel):
    uuid: str
    name: str
    author: str | None = None
    category: str | None = None
    group: str | None = None
    rule_id: str | None = None
    origin: str | None = None
    parse_status: str
    msgid_count: int
    finding_count: int
    table_reads: list[str]
    scoped: bool
    #: Находки без вердикта «принято». Именно они требуют внимания:
    #: принятая находка — это уже принятое решение, а не долг.
    open_finding_count: int
    #: Наибольшая тяжесть среди открытых находок: high | medium | low.
    #: None означает, что открытых находок нет.
    max_severity: str | None = None
    attack: RuleAttack
    #: Из списка объектов KB (снапшот по API): None — снапшот из файла или
    #: правило в списке KB не найдено; тогда «не установлено» не утверждается.
    installed: bool | None = None
    folder_path: str | None = None
    #: kb_id наборов установки; имена — в GET /snapshots/{id}/deployment-sets.
    deployment_sets: list[str] = []


class RuleListResponse(BaseModel):
    total: int
    items: list[RuleListItem]


def _table_reads_by_rule(db: Session, snapshot_id: int) -> dict[str, list[str]]:
    rows = (
        db.query(RuleTableRef.rule_uuid, RuleTableRef.table_name)
        .filter(RuleTableRef.snapshot_id == snapshot_id, RuleTableRef.direction == "read")
        .all()
    )
    out: dict[str, list[str]] = {}
    for rule_uuid, table_name in rows:
        out.setdefault(rule_uuid, []).append(table_name)
    return out


def _attack_of(db: Session, rule: RuleRow, markup: dict[str, Any]) -> RuleAttack:
    """Разметка одного правила.

    Ключ — UUID правила: разметка ведётся по правилу. Имя группы остаётся
    в ответе, потому что по нему по-прежнему группируют на экране.
    """
    group = group_key(rule)
    row = markup.get(rule.uuid)
    if row is None:
        return RuleAttack(status=STATUS_UNMAPPED, group=group or None)
    by_id = current_bundle(db).by_id()
    briefs = []
    for technique in techniques_of(row):
        described = by_id.get(technique.technique_id)
        briefs.append(
            AttackTechniqueBrief(
                technique_id=technique.technique_id,
                name_ru=described.name_ru if described else None,
                name=described.name if described else technique.technique_id,
                tactics=described.tactics if described else [],
                confidence=technique.confidence,
                evidence=technique.evidence,
                source=technique.source,
            )
        )
    return RuleAttack(
        status=row.status,
        group=group or None,
        techniques=briefs,
        inherited=bool(row.inherited),
    )


def _counts_by_rule(db: Session, snapshot_id: int, model: Any, uuid_col: Any) -> dict[str, int]:
    rows = (
        db.query(uuid_col, func.count())
        .filter(model.snapshot_id == snapshot_id)
        .group_by(uuid_col)
        .all()
    )
    return dict(rows)


ATTACK_STATUSES = (STATUS_SUGGESTED, STATUS_CONFIRMED, STATUS_UNMAPPED)


def _needs_attention(r: RuleRow, attention: dict[str, tuple[int, str | None]]) -> bool:
    """«Требует внимания» — как маркировка на экране (`attentionLevel`): не разобрано или есть открытые находки."""
    return r.parse_status != "ok" or attention.get(r.uuid, (0, None))[0] > 0


def _rules(
    db: Session, snapshot_id: int, *, author: str | None, category: str | None, group: str | None, q: str | None,
    attention_only: bool, scoped: bool, attack: str | None,
    installed: bool | None = None, deployment_set: str | None = None, folder: str | None = None,
) -> tuple[list[RuleRow], dict[str, Any], dict[str, tuple[int, str | None]]]:
    """Отобранные правила по имени, разметка и внимание по правилу. «Внимание» и статус разметки считаются
    не в SQL, поэтому отбор — целиком, страница — потом; правил тысячи, тело правила не читается."""
    if attack not in (None, "", "all", *ATTACK_STATUSES):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"неизвестный статус разметки «{attack}»")
    query = db.query(RuleRow).options(defer(RuleRow.body_text)).filter(RuleRow.snapshot_id == snapshot_id)
    if author:
        query = query.filter(RuleRow.author == author)
    if category:
        query = query.filter(RuleRow.type_id_cat == category)
    if group:
        query = query.filter(RuleRow.type_id_group == group)
    if q:
        query = query.filter(RuleRow.name.ilike(f"%{q}%"))
    if scoped:
        query = query.filter(RuleRow.scoped_by_list.is_(True))
    rows = query.order_by(RuleRow.name).all()
    markup = markup_by_rule(db)
    attention = attention_by_rule(db, snapshot_id)
    if attention_only:
        rows = [r for r in rows if _needs_attention(r, attention)]
    if attack and attack != "all":
        rows = [r for r in rows if (markup[r.uuid].status if r.uuid in markup else STATUS_UNMAPPED) == attack]
    if installed is not None or deployment_set or folder:
        # Инвентарь базы знаний (снапшот по API): те же три отбора, что на странице.
        deployment = deployment_by_rule(db, snapshot_id)
        rows = [
            r for r in rows
            if _inventory_matches(rule_fields(deployment.get(r.uuid.lower())), installed, deployment_set, folder)
        ]
    return rows, markup, attention


def _inventory_matches(fields: dict[str, Any], installed: bool | None, deployment_set: str | None, folder: str | None) -> bool:
    """Правило без строки инвентаря (`installed is None`) ни под один отбор установки не подходит."""
    if installed is not None and fields["installed"] is not installed:
        return False
    if deployment_set and deployment_set not in fields["deployment_sets"]:
        return False
    return not (folder and (fields["folder_path"] or "").split("/")[0] != folder)


@router.get("", response_model=RuleListResponse)
def list_rules(
    snapshot_id: int = Query(...),
    author: str | None = None,
    category: str | None = None,
    group: str | None = None,
    q: str | None = None,
    attention: bool = False,
    scoped: bool = False,
    attack: str | None = None,
    installed: bool | None = None,
    deployment_set: str | None = None,
    folder: str | None = None,
    # Страница инвентаря читает снапшот целиком и строит фасеты у себя: предел должен
    # вмещать базу заказчика (тысячи правил), а не резать её по тысяче.
    limit: int = Query(default=500, ge=1, le=20000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> RuleListResponse:
    """`attention` — только требующие внимания, `scoped` — только ограниченные списком, `attack` — статус
    разметки (suggested | confirmed | unmapped): те же отборы, что делает страница, — выгрузка их применяет."""
    found, markup, attention_map = _rules(db, snapshot_id, author=author, category=category, group=group, q=q,
                                          attention_only=attention, scoped=scoped, attack=attack,
                                          installed=installed, deployment_set=deployment_set, folder=folder)
    total = len(found)
    rows = found[offset : offset + limit]

    table_reads = _table_reads_by_rule(db, snapshot_id)
    msgid_counts = _counts_by_rule(
        db,
        snapshot_id,
        RuleMsgid,
        RuleMsgid.rule_uuid,
    ) if rows else {}
    finding_counts: dict[str, int] = dict(
        db.query(FindingRow.object_uuid, func.count())
        .filter(FindingRow.snapshot_id == snapshot_id)
        .group_by(FindingRow.object_uuid)
        .all()  # type: ignore[arg-type]
    )

    deployment = deployment_by_rule(db, snapshot_id)

    items = [
        RuleListItem(
            uuid=r.uuid,
            name=r.name,
            author=r.author,
            category=r.type_id_cat,
            group=r.type_id_group,
            rule_id=r.type_id_num,
            origin=r.origin,
            parse_status=r.parse_status,
            msgid_count=msgid_counts.get(r.uuid, 0),
            finding_count=finding_counts.get(r.uuid, 0),
            table_reads=table_reads.get(r.uuid, []),
            scoped=r.scoped_by_list,
            open_finding_count=attention_map.get(r.uuid, (0, None))[0],
            max_severity=attention_map.get(r.uuid, (0, None))[1],
            attack=_attack_of(db, r, markup),
            **rule_fields(deployment.get(r.uuid.lower())),
        )
        for r in rows
    ]
    return RuleListResponse(total=total, items=items)


def _detail_deployment(db: Session, snapshot_id: int, rule_uuid: str) -> dict[str, Any]:
    """В детали — имена наборов, а не их id: здесь место для слов."""
    fields = rule_fields(deployment_by_rule(db, snapshot_id).get(rule_uuid.lower()))
    names = set_names(db, snapshot_id)
    fields["deployment_sets"] = [names.get(kb_id, kb_id) for kb_id in fields["deployment_sets"]]
    return fields


#: Подписи маркировки — как на экране (AttentionBadge); разметка — техники и её статус словами.
ATTENTION_TITLES = {"unparsed": "Не разобрано", "high": "Разобрать", "medium": "Посмотреть", "clean": "Чисто"}
ATTACK_TITLES = {STATUS_SUGGESTED: "предложено", STATUS_CONFIRMED: "подтверждено"}

EXPORT_COLUMNS = [
    Column("name", "Имя"), Column("author", "Автор"), Column("category", "Категория"), Column("msgid", "msgid"),
    Column("attention", "Внимание"), Column("attack", "ATT&CK"), Column("scoped", "Ограничено"),
    Column("installed", "В SIEM"),
]


def _installed_cell(installed: bool | None) -> str:
    """Как на экране: без инвентаря — пусто, а не «не установлено»."""
    if installed is None:
        return ""
    return "в SIEM" if installed else "не установлено"


def _attention_cell(r: RuleRow, attention: dict[str, tuple[int, str | None]]) -> str:
    count, worst = attention.get(r.uuid, (0, None))
    if r.parse_status != "ok":
        level = "unparsed"
    elif count == 0:
        level = "clean"
    else:
        level = "high" if worst == "high" else "medium"
    return ATTENTION_TITLES[level] + (f" {count}" if count > 0 else "")


def _attack_cell(row: Any) -> str | None:
    """Техники разметки через запятую и её статус; без разметки — пусто, как «—» на экране."""
    if row is None:
        return None
    ids = [t.technique_id for t in techniques_of(row)]
    if not ids:
        return None
    return f"{', '.join(ids)} ({ATTACK_TITLES.get(row.status, row.status)})"


@router.get("/export")
def export_rules(
    snapshot_id: int = Query(...),
    author: str | None = None,
    category: str | None = None,
    group: str | None = None,
    q: str | None = None,
    attention: bool = False,
    scoped: bool = False,
    attack: str | None = None,
    installed: bool | None = None,
    deployment_set: str | None = None,
    folder: str | None = None,
    fmt: str = Query(default="csv", alias="format"),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    """Правила под теми же отборами, что на странице, в порядке списка (объявлена до `/{rule_uuid}`).
    Тело правила, как и в списке, не выгружается."""
    found, markup, attention_map = _rules(db, snapshot_id, author=author, category=category, group=group, q=q,
                                          attention_only=attention, scoped=scoped, attack=attack,
                                          installed=installed, deployment_set=deployment_set, folder=folder)
    msgids = _counts_by_rule(db, snapshot_id, RuleMsgid, RuleMsgid.rule_uuid)
    deployment = deployment_by_rule(db, snapshot_id)
    rows = [
        {"name": r.name, "author": r.author, "category": f"{r.type_id_cat or ''}/{r.type_id_group or ''}", "msgid": msgids.get(r.uuid, 0),
         "attention": _attention_cell(r, attention_map), "attack": _attack_cell(markup.get(r.uuid)),
         "scoped": "да" if r.scoped_by_list else "нет",
         "installed": _installed_cell(rule_fields(deployment.get(r.uuid.lower()))["installed"])}
        for r in found
    ]
    return export_response(fmt, EXPORT_COLUMNS, rows, module="siem", name="rules")


@router.get("/{rule_uuid}")
def get_rule(
    rule_uuid: str,
    snapshot_id: int = Query(...),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    rule = (
        db.query(RuleRow)
        .filter(RuleRow.snapshot_id == snapshot_id, RuleRow.uuid == rule_uuid)
        .one_or_none()
    )
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="правило не найдено")

    msgid_rows = (
        db.query(RuleMsgid)
        .filter(RuleMsgid.snapshot_id == snapshot_id, RuleMsgid.rule_uuid == rule_uuid)
        .all()
    )
    own_msgids = sorted(m.msgid for m in msgid_rows if not m.inherited)
    inherited_msgids = sorted(m.msgid for m in msgid_rows if m.inherited)

    parents = sorted(
        row.parent
        for row in db.query(RuleDependency).filter(
            RuleDependency.snapshot_id == snapshot_id, RuleDependency.child == rule.name
        )
    )
    children = sorted(
        row.child
        for row in db.query(RuleDependency).filter(
            RuleDependency.snapshot_id == snapshot_id, RuleDependency.parent == rule.name
        )
    )

    table_reads = sorted(
        row.table_name
        for row in db.query(RuleTableRef).filter(
            RuleTableRef.snapshot_id == snapshot_id,
            RuleTableRef.rule_uuid == rule_uuid,
            RuleTableRef.direction == "read",
        )
    )
    table_writes = sorted(
        row.table_name
        for row in db.query(RuleTableRef).filter(
            RuleTableRef.snapshot_id == snapshot_id,
            RuleTableRef.rule_uuid == rule_uuid,
            RuleTableRef.direction == "write",
        )
    )
    # Состояние читаемых списков — рядом с телом: правило, читающее
    # отсутствующий или пустой список, не сработает ни на чём, а в теле
    # имя списка выглядит так же, как имя исправного. Размер — число
    # значений, та же мера, по которой список считается пустым везде.
    sizes: dict[str, int] = {
        name: count
        for name, count in db.query(TableListRow.name, TableListRow.value_count).filter(
            TableListRow.snapshot_id == snapshot_id, TableListRow.name.in_(table_reads)
        )
    }
    tables = [
        {"name": name, "exists": name in sizes, "value_count": sizes.get(name)}
        for name in table_reads
    ]

    finding_rows = (
        db.query(FindingRow)
        .filter(FindingRow.snapshot_id == snapshot_id, FindingRow.object_uuid == rule_uuid)
        .all()
    )
    salt, _ = display_salt(db)
    keys = {f.id: key_of(salt, f) for f in finding_rows}
    states = finding_svc.state_map(db, MODULE, SCOPE, keys.values())
    counted = finding_svc.counted_statuses(db)
    status_of = {f.id: finding_svc.effective_status(states.get(keys[f.id])) for f in finding_rows}
    # Значение нужно здесь только чтобы найти его место в теле: наружу
    # оно не уходит, клиент получает отрезки и класс.
    findings_with_values = [
        {"kind": f.kind, "value": f.value, "status": status_of[f.id], "counted": status_of[f.id] in counted}
        for f in finding_rows
    ]

    findings = [
        {
            "id": f.id,
            "kind": f.kind,
            "severity": f.severity,
            "field": f.field,
            "polarity": f.polarity,
            "in_table": f.in_table,
            "table_name": f.table_name,
            "status": status_of[f.id],
            "counted": status_of[f.id] in counted,
            "has_value": bool(f.value),
        }
        for f in finding_rows
    ]

    return {
        "uuid": rule.uuid,
        "name": rule.name,
        "author": rule.author,
        "category": rule.type_id_cat,
        "group": rule.type_id_group,
        "rule_id": rule.type_id_num,
        "origin": rule.origin,
        "parse_status": rule.parse_status,
        "title_ru": rule.title_ru,
        "title_en": rule.title_en,
        "description_ru": rule.description_ru,
        "description_en": rule.description_en,
        "body_hash": rule.body_hash,
        "scoped": rule.scoped_by_list,
        "msgids": {"own": own_msgids, "inherited": inherited_msgids},
        "dependencies": {"parents": parents, "children": children},
        "table_reads": table_reads,
        "table_writes": table_writes,
        "tables": tables,
        "findings": findings,
        "attack": _attack_of(db, rule, markup_by_rule(db)).model_dump(),
        **_detail_deployment(db, snapshot_id, rule.uuid),
        "body": rule.body_text,
        # Где в теле сидит каждое замечание. Тело и так показывается
        # целиком, так что подсветка ничего не раскрывает — она отвечает
        # на вопрос «где именно», который иначе решается поиском глазами
        # среди сотни замечаний.
        "body_spans": [s.model_dump() for s in spans_for(rule.body_text, findings_with_values)],
    }
