"""Разметка по ATT&CK: покрытие, группы, запуск, подтверждение, слой.

Разметка живёт вне снапшотов и привязана к группе правил. Предложение
модели и подтверждение человека различаются в самом ответе, а не только
на экране: ошибки разметки тихие — неверная техника годами живёт в отчёте
и никого не смущает.
"""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import (
    AppUser,
    AttackMarkup,
    AttackReference,
    Job,
    Snapshot,
)
from api.deps import get_current_user
from api.limits import SIEM_REFERENCE_UPLOAD, check_upload_size
from api.modules.attack.layers import parent_of
from api.modules.attack.services.attack_bundle import current as current_bundle
from api.modules.siem.services.appsettings import load_llm
from api.modules.siem.services.attack import (
    SOURCE_MANUAL,
    STATUS_CONFIRMED,
    STATUS_UNMAPPED,
    MarkupTechnique,
    markup_by_rule,
    run_markup,
    techniques_of,
)
from api.modules.siem.services.attack_layer import rules_of, state_by_technique
from api.modules.siem.services.reference import apply_reference, import_reference
from api.modules.siem.services.reference import compare as compare_reference
from api.modules.siem.services.rule_attention import group_key, rules_of_group
from kbaudit.attack.prevalence import load_revoked, migrate
from kbaudit.attack.reference import parse as reference_parse

router = APIRouter(prefix="/attack", tags=["attack"])

#: Раскраска слоя Navigator. Категориальная, а не градиент: состояния
#: различаются по существу, а не по степени. Цвета подобраны так, чтобы
#: различаться и в чёрно-белой печати, а подпись в legendItems обязательна —
#: слой читают люди, которые не видели этот интерфейс.
_LAYER_COLORS = {
    STATUS_CONFIRMED: "#2e7d32",
    "suggested": "#f9a825",
    STATUS_UNMAPPED: "#9e9e9e",
}


class ConfirmRequest(BaseModel):
    """Подтверждение разметки: одного правила или всей группы разом.

    Группа осталась как способ разметить однородную пачку одним движением —
    на выгрузке заказчика 14 групп из 32 действительно сходятся на одной
    технике. Но записывается такое подтверждение всё равно по правилам,
    каждому своё, и уточнить любое из них потом можно отдельно.
    """

    snapshot_id: int
    rule_uuid: str | None = None
    group: str | None = None
    techniques: list[str] = Field(default_factory=list)
    reason: str | None = None


class RunRequest(BaseModel):
    snapshot_id: int


def _snapshot(db: Session, snapshot_id: int) -> Snapshot:
    row = db.get(Snapshot, snapshot_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="снапшот не найден")
    return row


def _describe(db: Session, technique_id: str, confidence: str = "", evidence: str = "",
              source: str = "") -> dict[str, Any]:
    book = current_bundle(db).by_id()
    technique = book.get(technique_id)
    moved_from: str | None = None
    if technique is None:
        # MITRE переносит отозванные техники сама и оставляет указатель.
        # Заставлять человека заново размечать то, что уже перенесено за
        # него, — лишняя работа: в 19-й версии одна лишь перестройка
        # семейства T1562 задевает всю разметку по обходу защиты.
        replacement = migrate(technique_id, load_revoked(), set(book))
        if replacement is not None:
            technique = book.get(replacement)
            moved_from, technique_id = technique_id, replacement
    return {
        "technique_id": technique_id,
        "name_ru": technique.name_ru if technique else None,
        "name": technique.name if technique else technique_id,
        "tactics": technique.tactics if technique else [],
        "confidence": confidence,
        "evidence": evidence,
        "source": source,
        # Техники нет в действующей матрице: её отозвали или переименовали
        # при обновлении. Без пометки в интерфейсе остался бы голый
        # идентификатор без названия, и молча.
        "missing": technique is None,
        # Перенос показывается, а не применяется молча: разметку
        # подтверждал человек, и подменять его решение без его ведома
        # нельзя — даже если подменяешь на правильное.
        "moved_from": moved_from,
    }


def _group_summaries(db: Session, snapshot_id: int) -> dict[str, dict[str, Any]]:
    """Свод разметки по группам, собранный из разметки правил.

    Группа перестала быть единицей разметки, но осталась единицей чтения:
    на экране человек по-прежнему смотрит на группы. Состояние группы —
    самое слабое среди её правил: группа, где размечено девятнадцать
    правил из двадцати одного, не размечена целиком, и показывать её
    подтверждённой значит скрывать оставшуюся работу.
    """
    _snapshot(db, snapshot_id)
    markup = markup_by_rule(db)
    rank = {STATUS_UNMAPPED: 0, "suggested": 1, STATUS_CONFIRMED: 2}
    out: dict[str, dict[str, Any]] = {}
    for rule in sorted(rules_of(db, snapshot_id), key=lambda r: r.name):
        group = group_key(rule)
        if not group:
            continue
        row = markup.get(rule.uuid)
        state = row.status if row is not None else STATUS_UNMAPPED
        bucket = out.setdefault(
            group,
            {
                "group": group,
                "rule_count": 0,
                "unmapped_rules": 0,
                "confirmed_rules": 0,
                "inherited_rules": 0,
                "techniques": {},
                "candidates": [],
                "model": None,
                "attack_version": None,
                "reviewed_by": None,
                "reviewed_at": None,
                "_ranks": [],
            },
        )
        bucket["rule_count"] += 1
        bucket["_ranks"].append(rank[state])
        if state == STATUS_UNMAPPED:
            bucket["unmapped_rules"] += 1
        if state == STATUS_CONFIRMED:
            bucket["confirmed_rules"] += 1
        if row is None:
            continue
        if row.inherited:
            bucket["inherited_rules"] += 1
        bucket["model"] = bucket["model"] or row.model
        bucket["attack_version"] = bucket["attack_version"] or row.attack_version
        bucket["reviewed_by"] = bucket["reviewed_by"] or row.reviewed_by
        if row.reviewed_at and not bucket["reviewed_at"]:
            bucket["reviewed_at"] = row.reviewed_at.isoformat()
        if not bucket["candidates"]:
            bucket["candidates"] = json.loads(row.candidates_json or "[]")
        for technique in techniques_of(row):
            bucket["techniques"].setdefault(
                technique.technique_id,
                _describe(
                    db, technique.technique_id, technique.confidence,
                    technique.evidence, technique.source,
                ),
            )

    by_rank = {v: k for k, v in rank.items()}
    for bucket in out.values():
        bucket["status"] = by_rank[min(bucket.pop("_ranks") or [0])]
        bucket["techniques"] = list(bucket["techniques"].values())
    return out


@router.get("/coverage")
def coverage(
    snapshot_id: int = Query(...),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    _snapshot(db, snapshot_id)
    rules = rules_of(db, snapshot_id)
    markup = markup_by_rule(db)
    by_status = {STATUS_CONFIRMED: 0, "suggested": 0, STATUS_UNMAPPED: 0}
    covered: set[str] = set()
    by_tactic: dict[str, int] = {}
    model: str | None = None
    inherited = 0

    # Считается по правилам: единица разметки теперь правило. Прежний
    # счёт по группам показывал сорок восемь решений там, где их сто
    # восемьдесят семь, и работа выглядела почти сделанной.
    for rule in rules:
        row = markup.get(rule.uuid)
        status_name = row.status if row is not None else STATUS_UNMAPPED
        by_status[status_name] = by_status.get(status_name, 0) + 1
        if row is None:
            continue
        if row.inherited:
            inherited += 1
        model = model or row.model
        for technique in techniques_of(row):
            covered.add(technique.technique_id)

    live = current_bundle(db)
    missing: set[str] = set()
    for technique_id in covered:
        described = live.by_id().get(technique_id)
        if described is None:
            # Подтехники может не быть в матрице как отдельной записи,
            # но родитель есть — тогда техника закрыта, а не исчезла.
            described = live.by_id().get(parent_of(technique_id))
        if described is None:
            missing.add(technique_id)
            continue
        for tactic in described.tactics:
            by_tactic[tactic] = by_tactic.get(tactic, 0) + 1

    outdated = sum(
        1
        for rule in rules
        if (row := markup.get(rule.uuid)) is not None
        and row.attack_version
        and row.attack_version != live.version
    )

    return {
        "attack_version": current_bundle(db).version,
        "rule_count": len(rules),
        "group_count": len({group_key(r) for r in rules if group_key(r)}),
        # Правил, чья разметка досталась от группы и для них не уточнялась.
        # Это работа, которая выглядит сделанной, но не сделана.
        "inherited": inherited,
        "confirmed": by_status[STATUS_CONFIRMED],
        "suggested": by_status["suggested"],
        "unmapped": by_status[STATUS_UNMAPPED],
        "techniques_covered": len(covered),
        "by_tactic": dict(sorted(by_tactic.items(), key=lambda kv: -kv[1])),
        "model": model,
        # Пустой адрес — законное состояние, а не ошибка. Интерфейс должен
        # объяснять, что разметка недоступна, а не показывать ноль как факт.
        "llm_configured": load_llm(db).configured,
        # Разметка, сделанная на другой версии матрицы, и техники, которых
        # в ней больше нет: и то и другое требует пересмотра человеком.
        "outdated_groups": outdated,
        "missing_techniques": sorted(missing),
    }


@router.get("/groups")
def groups(
    snapshot_id: int = Query(...),
    status_filter: str | None = Query(default=None, alias="status"),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    live_version = current_bundle(db).version
    summaries = _group_summaries(db, snapshot_id)
    items: list[dict[str, Any]] = []
    for group in sorted(summaries):
        bucket = summaries[group]
        if status_filter and bucket["status"] != status_filter:
            continue
        items.append(
            {
                **bucket,
                # Разметка подтверждена на другой версии матрицы: техника
                # с тех пор могла переехать, раздробиться на подтехники
                # или быть отозванной. Это повод пересмотреть, а не ошибка.
                "version_outdated": bool(
                    bucket["attack_version"] and bucket["attack_version"] != live_version
                ),
            }
        )
    return {"total": len(items), "items": items}


@router.post("/run", status_code=status.HTTP_202_ACCEPTED)
def run(
    payload: RunRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, int]:
    _snapshot(db, payload.snapshot_id)
    if not load_llm(db).configured:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="адрес модели не задан — задайте его в настройках",
        )
    job = Job(snapshot_id=payload.snapshot_id, stage="pending", status="running", progress=0)
    db.add(job)
    db.commit()
    db.refresh(job)
    background_tasks.add_task(run_markup, job.id, payload.snapshot_id)
    return {"job_id": job.id}


@router.post("/confirm", status_code=status.HTTP_204_NO_CONTENT)
def confirm(
    payload: ConfirmRequest,
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> None:
    """Подтверждение разметки человеком.

    Пустой список техник — тоже решение: «это правило ни одной технике
    не соответствует» отличается от «ещё не смотрели», и первое не должно
    выглядеть как второе.
    """
    known = current_bundle(db).by_id()
    unknown = [t for t in payload.techniques if t not in known]
    if unknown:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"неизвестные техники: {', '.join(sorted(unknown))}",
        )
    if bool(payload.rule_uuid) == bool(payload.group):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="подтверждать нужно либо правило, либо группу",
        )

    _snapshot(db, payload.snapshot_id)
    rules = rules_of(db, payload.snapshot_id)
    if payload.rule_uuid:
        targets = [r for r in rules if r.uuid == payload.rule_uuid]
        if not targets:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="правило не найдено")
    else:
        targets = [r for r in rules if group_key(r) == payload.group]
        if not targets:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="группа не найдена")

    now = dt.datetime.now(dt.UTC)
    version = current_bundle(db).version
    for rule in targets:
        row = (
            db.query(AttackMarkup).filter(AttackMarkup.rule_uuid == rule.uuid).one_or_none()
        )
        if row is None:
            row = AttackMarkup(rule_uuid=rule.uuid)
            db.add(row)
        row.group_name = group_key(rule)

        # Уверенность и обоснование модели сохраняются для тех техник, которые
        # человек оставил: он согласился с ними, а не переписал заново.
        previous = {t.technique_id: t for t in techniques_of(row)}
        row.techniques_json = json.dumps(
            [
                MarkupTechnique(
                    technique_id=t,
                    confidence=previous[t].confidence if t in previous else "",
                    evidence=previous[t].evidence if t in previous else "",
                    source=previous[t].source if t in previous else SOURCE_MANUAL,
                ).model_dump()
                for t in payload.techniques
            ],
            ensure_ascii=False,
        )
        row.status = STATUS_CONFIRMED
        # Подтверждение группой распространяется на её правила, и для
        # каждого в отдельности оно по-прежнему не проверено. Пометка
        # об этом снимается, только когда человек открыл само правило.
        row.inherited = payload.group is not None
        row.reviewed_by = user.login
        row.reviewed_at = now
        row.reason = payload.reason
        row.attack_version = row.attack_version or version
    db.commit()


@router.get("/layer/{snapshot_id}")
def layer(
    snapshot_id: int,
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Слой для ATT&CK Navigator 4.5.

    Раскраска категориальная и обязательно снабжена legendItems: слой
    открывают в чужом инструменте, где нет ни этого интерфейса, ни
    объяснения, чем предложение модели отличается от подтверждения.
    """
    _snapshot(db, snapshot_id)
    states, groups_by_technique = state_by_technique(db, snapshot_id)

    techniques_layer = [
        {
            "techniqueID": technique_id,
            "color": _LAYER_COLORS.get(state, _LAYER_COLORS[STATUS_UNMAPPED]),
            "comment": "Группы: " + ", ".join(groups_by_technique.get(technique_id, [])),
            "enabled": True,
        }
        for technique_id, state in sorted(states.items())
    ]

    return {
        "name": f"SIEM Rules Analyzer — снапшот {snapshot_id}",
        "versions": {"attack": current_bundle(db).version or "", "navigator": "4.5", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            "Покрытие правилами детекта. Жёлтое — предложено моделью и не проверено человеком."
        ),
        "techniques": techniques_layer,
        "legendItems": [
            {"label": "Подтверждено человеком", "color": _LAYER_COLORS[STATUS_CONFIRMED]},
            {"label": "Предложено моделью, не проверено", "color": _LAYER_COLORS["suggested"]},
        ],
        "showTacticRowBackground": False,
        "hideDisabled": False,
    }


# --------------------------------------------------------------------------
# Подробности: группа
# --------------------------------------------------------------------------


@router.get("/group")
def group_detail(
    group: str = Query(...),
    snapshot_id: int = Query(...),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Всё о группе: её правила с маркировкой и её разметка.

    Группа — единица разметки, и решение о ней принимают, глядя на её
    правила. Список из одних имён для этого не годится: важно, какие
    из них разобраны и у каких есть открытые замечания.
    """
    summaries = _group_summaries(db, snapshot_id)
    if group not in summaries:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="группа не найдена")

    bucket = summaries[group]
    markup = markup_by_rule(db)
    live_version = current_bundle(db).version
    # У каждого правила своя разметка: группа больше не говорит за всех,
    # и в её карточке должно быть видно, где правила расходятся.
    rules = [
        {
            **brief,
            "status": (row.status if (row := markup.get(brief["uuid"])) else STATUS_UNMAPPED),
            "inherited": bool(row.inherited) if row else False,
            "techniques": [t.technique_id for t in techniques_of(row)] if row else [],
        }
        for brief in rules_of_group(db, snapshot_id, group)
    ]
    return {
        **bucket,
        "reason": next(
            (r.reason for r in markup.values() if r.group_name == group and r.reason), None
        ),
        "version_outdated": bool(
            bucket["attack_version"] and bucket["attack_version"] != live_version
        ),
        "rules": rules,
        # Сводка по группе: сколько её правил требуют внимания. Разметка
        # группы, половина правил которой не разобрана, стоит меньше.
        "unparsed": sum(1 for r in rules if r["parse_status"] != "ok"),
        "with_findings": sum(1 for r in rules if r["open_finding_count"]),
    }


# --------------------------------------------------------------------------
# Эталонная разметка
# --------------------------------------------------------------------------


@router.post("/reference")
def upload_reference(
    snapshot_id: int = Query(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Загрузить чужую таблицу «правило → техника» как эталон.

    Файл не покидает периметр и никуда не отправляется: он разбирается
    на месте и ложится в базу рядом с нашей разметкой. Подменять ею
    разметку продукт не станет — эталон нужен, чтобы видеть разницу.
    """
    data = file.file.read()
    if not data:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail="файл пуст")
    check_upload_size(len(data), SIEM_REFERENCE_UPLOAD)
    try:
        parsed = reference_parse(data, file.filename or "")
    except ValueError as exc:
        # В том числе xlsx, распакованный больше лимита (kbaudit.safe_io).
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"файл не разобран: {exc}") from exc
    if not parsed.rows:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "в файле не нашлось ни строки с идентификатором правила и техникой ATT&CK. "
                "Нужны колонка с идентификатором правила и колонка с техниками вида T1059"
            ),
        )
    return import_reference(db, parsed, snapshot_id, file.filename or "файл", user.login)


@router.get("/reference/compare")
def reference_compare(
    snapshot_id: int = Query(...),
    verdict: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Сверка нашей разметки с эталоном.

    Итог по каждому правилу, а не одно число: «совпало 3 из 32» ничего
    не подсказывает, а список расхождений — подсказывает.
    """
    result = compare_reference(db, snapshot_id)
    if verdict:
        result["items"] = [i for i in result["items"] if i["verdict"] == verdict]
    return result


class ApplyReferenceRequest(BaseModel):
    """Что именно принять из эталона."""

    snapshot_id: int
    #: Одно правило. Без него принимается всё, что отобрано `verdicts`.
    rule_uuid: str | None = None
    #: Итоги сверки, которые принимаются: например только «расхождение»
    #: и «у нас нет разметки». Пусто — принять по всем сверенным правилам.
    verdicts: list[str] = Field(default_factory=list)


@router.post("/reference/apply")
def apply_reference_endpoint(
    payload: ApplyReferenceRequest,
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Принять эталон как разметку.

    Разметка записывается с источником `reference` и статусом
    «подтверждено»: это решение человека, пусть и принятое в чужом
    документе. Следствие важное — последующие прогоны модели её не
    трогают, и принятый эталон не будет затёрт кнопкой «разметить
    моделью».
    """
    return apply_reference(
        db,
        payload.snapshot_id,
        user.login,
        rule_uuid=payload.rule_uuid,
        verdicts=payload.verdicts or None,
    )


@router.delete("/reference", status_code=status.HTTP_204_NO_CONTENT)
def drop_reference(
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> None:
    """Убрать эталон. Своей разметки это не касается."""
    db.query(AttackReference).delete()
    db.commit()
