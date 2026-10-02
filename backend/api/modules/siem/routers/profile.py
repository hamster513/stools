"""Профиль инсталляции.

PUT пересчитывает производные числа снапшота синхронно, в рамках того же
запроса: разбор архива не повторяется — `ParsedArchive` берётся из JSON-кэша,
записанного при загрузке (см. api/services/ingest.py), пересобирается
только `AuditReport` (объёмы это позволяют — секунды на всю выгрузку,
дизайн-спека §3.3).
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser, RuleField, Snapshot, SnapshotProfile
from api.deps import get_current_user
from api.modules.siem.findings_adapter import reconcile as reconcile_findings
from api.modules.siem.findings_adapter import stamp as stamp_analysis
from api.modules.siem.services.persist import persist_report
from kbaudit.analyzers.fields import builtin_account_names, builtin_field_roles
from kbaudit.analyzers.mp_taxonomy import role_by_documentation
from kbaudit.models import ParsedArchive
from kbaudit.naming import NameScheme
from kbaudit.profile import FieldRoles, Profile, TableRoles, detect_profile
from kbaudit.report import build_report

router = APIRouter(prefix="/profile", tags=["profile"])


class ProfilePutRequest(BaseModel):
    snapshot_id: int
    tables: TableRoles = Field(default_factory=TableRoles)
    builtin_accounts: list[str] = Field(default_factory=list)
    field_roles: FieldRoles = Field(default_factory=FieldRoles)
    name_scheme: NameScheme | None = None


def _get_snapshot(db: Session, snapshot_id: int) -> Snapshot:
    snapshot = db.get(Snapshot, snapshot_id)
    if snapshot is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="снапшот не найден")
    return snapshot


@router.get("")
def get_profile(
    snapshot_id: int = Query(...),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    _get_snapshot(db, snapshot_id)
    row = db.get(SnapshotProfile, snapshot_id)
    profile = (
        Profile()
        if row is None or row.profile_json in ("{}", "", None)
        else Profile.model_validate_json(row.profile_json)
    )
    out = profile.model_dump(mode="json")
    # Что уже учтено без настройки. Без этого пустой список в интерфейсе
    # читается как «ничего не исключается», хотя исключается многое:
    # SYSTEM, NETWORK SERVICE и учётные записи компьютеров.
    out["builtin_accounts_default"] = builtin_account_names()
    out["field_roles_default"] = builtin_field_roles()
    return out


@router.get("/fields")
def profile_fields(
    snapshot_id: int = Query(...),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Поля таксономии, которые правила действительно используют.

    С их ролью: средовое, техническое или неизвестное. Последних больше
    всего, и это важно знать: поле без роли не анализируется вовсе, то
    есть захардкоженное в нём значение проходит мимо молча.
    """
    snapshot = _get_snapshot(db, snapshot_id)
    profile = _load_profile_row(db, snapshot_id)
    builtin = builtin_field_roles()
    # Роли из самой таксономии выгрузки — то, что вендор написал о своих
    # полях. Показываются отдельно от встроенного списка инструмента:
    # источник роли говорит, насколько ей можно верить.
    taxonomy_roles = _load_parsed(snapshot).taxonomy.field_roles
    own_env = set(profile.field_roles.environmental)
    own_tech = set(profile.field_roles.technical)

    counts: dict[str, int] = {}
    for field, in db.query(RuleField.field).filter(RuleField.snapshot_id == snapshot_id):
        counts[field] = counts.get(field, 0) + 1

    def role_and_source(name: str) -> tuple[str, str]:
        """Роль и то, откуда она взялась.

        Порядок — от самого весомого источника: решение человека,
        затем описание поля в таксономии, затем встроенный список
        инструмента.
        """
        if name in own_env:
            return "environmental", "profile"
        if name in own_tech:
            return "technical", "profile"
        if name in taxonomy_roles:
            # Роль выведена либо из машиночитаемого описания поля
            # в taxonomy.json, либо из таблицы по документации MP SIEM.
            # Различать источники стоит: первое сказано о самой выгрузке,
            # второе — о продукте вообще.
            source = "documentation" if role_by_documentation(name) else "taxonomy"
            return taxonomy_roles[name], source
        if name in builtin["environmental"]:
            return "environmental", "builtin"
        if name in builtin["technical"]:
            return "technical", "builtin"
        return "unknown", "none"

    items = []
    for name, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        role, source = role_and_source(name)
        items.append(
            {
                "field": name,
                "rule_count": count,
                "role": role,
                "source": source,
                # Задано человеком, а не выведено: такую роль можно снять.
                "from_profile": source == "profile",
            }
        )
    return {
        "total": len(items),
        "unknown": sum(1 for i in items if i["role"] == "unknown"),
        "from_taxonomy": sum(
            1 for i in items if i["source"] in ("taxonomy", "documentation")
        ),
        "items": items,
    }


@router.post("/preview")
def preview_profile(
    payload: ProfilePutRequest,
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Что даст этот профиль, если его сохранить. Ничего не меняет.

    Решение о роли поля стоит дорого: одно поле на эталонной выгрузке
    добавляет до семидесяти замечаний. Принимать его вслепую, а потом
    искать, откуда взялась сотня новых находок, — плохой порядок.
    """
    snapshot = _get_snapshot(db, payload.snapshot_id)
    parsed = _load_parsed(snapshot)
    report = build_report(parsed, _profile_from(payload, None))
    return {
        "finding_count": report.finding_count,
        "scoped_count": report.scoped_count,
        "group_count": report.group_count,
    }


@router.get("/suggest")
def suggest_profile(
    snapshot_id: int = Query(...),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    snapshot = _get_snapshot(db, snapshot_id)
    parsed = _load_parsed(snapshot)
    draft = detect_profile([r.name for r in parsed.rules])
    return draft.model_dump(mode="json")


def _profile_from(payload: ProfilePutRequest, login: str | None) -> Profile:
    profile = Profile(
        tables=payload.tables,
        builtin_accounts=payload.builtin_accounts,
        field_roles=payload.field_roles,
        name_scheme=payload.name_scheme,
        confirmed_by=login,
    )
    if login is not None:
        profile.confirmed_at = dt.datetime.now(dt.UTC).isoformat()
    return profile


def _load_profile_row(db: Session, snapshot_id: int) -> Profile:
    row = db.get(SnapshotProfile, snapshot_id)
    if row is None or row.profile_json in ("{}", "", None):
        return Profile()
    return Profile.model_validate_json(row.profile_json)


def _load_parsed(snapshot: Snapshot) -> ParsedArchive:
    path = Path(snapshot.parsed_cache_path)
    if not path.is_file():
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="разбор снапшота ещё не завершён или не сохранился — попробуйте позже",
        )
    return ParsedArchive.model_validate_json(path.read_text(encoding="utf-8"))


@router.put("", status_code=status.HTTP_204_NO_CONTENT)
def put_profile(
    payload: ProfilePutRequest,
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> None:
    snapshot = _get_snapshot(db, payload.snapshot_id)
    parsed = _load_parsed(snapshot)

    profile = _profile_from(payload, user.login)

    row = db.get(SnapshotProfile, snapshot.id)
    if row is None:
        row = SnapshotProfile(snapshot_id=snapshot.id, profile_json="{}")
        db.add(row)
    row.profile_json = profile.model_dump_json()

    report = build_report(parsed, profile)
    persist_report(db, snapshot, parsed, report)
    stamp_analysis(snapshot, profile)
    db.commit()
    # Профиль меняет находки снапшота, но не базу знаний: автоматики статусов
    # нет, у строк обновляется только наличие (findings_adapter.reconcile).
    reconcile_findings(db, snapshot.id, upload=False)
