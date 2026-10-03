"""Содержимое одной политики: заголовок, сводка замков, секции настроек."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.ksc.core.export import ExportIndex, _int, _str, load_export_path
from api.modules.ksc.core.policy_contents import lock_summary, truncate_value, walk_settings
from api.modules.ksc.models import KscSnapshot
from api.modules.ksc.services.snapshots import snapshot_path
from api.settings import Settings, get_settings

router = APIRouter(tags=["ksc"])


class PolicyHeaderView(BaseModel):
    id: int
    name: str
    product: str
    version: str
    group: str


class LockSummaryView(BaseModel):
    total: int
    locked: int
    share: float
    #: Настройки с признаком замка; 0 — замки в политике не распознаны.
    with_lock_flag: int


class SettingView(BaseModel):
    path: str
    value: str
    locked: bool | None = None
    inherited_lock: bool
    lock_from: str


class SectionView(BaseModel):
    name: str
    settings: list[SettingView]


class PolicyContentsResponse(BaseModel):
    policy: PolicyHeaderView
    summary: LockSummaryView | None = None
    sections: list[SectionView]
    errors: list[str]


@router.get("/snapshots/{snapshot_id}/policies/{policy_id}/contents", response_model=PolicyContentsResponse)
def get_policy_contents(
    snapshot_id: int,
    policy_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> PolicyContentsResponse:
    snap = db.get(KscSnapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="снапшот не найден")
    path = snapshot_path(settings.data_dir, snap.id)
    if not path.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="файл выгрузки не найден")
    # Без хостов: нужен только путь группы, а записи хостов большой выгрузки строятся секундами.
    idx = ExportIndex(load_export_path(path).model_copy(update={"hosts": []}))
    policy = next((p for p in idx.export.policies if _int(p.get("KLPOL_ID")) == policy_id), None)
    if policy is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="политика не найдена")
    header = PolicyHeaderView(
        id=policy_id,
        name=_str(policy.get("KLPOL_DN")),
        product=_str(policy.get("KLPOL_PRODUCT")),
        version=_str(policy.get("KLPOL_VERSION")),
        group=idx.group_path(_int(policy.get("KLPOL_GROUP_ID"))),
    )
    content = idx.export.policy_contents.get(str(policy_id))
    if content is None:
        return PolicyContentsResponse(policy=header, summary=None, sections=[], errors=["содержимое не собрано"])

    settings_list = walk_settings(content.get("sections", {}))
    summary = lock_summary(settings_list)
    by_section: dict[str, list[SettingView]] = {}
    for s in settings_list:
        by_section.setdefault(s.section, []).append(
            SettingView(path=s.path, value=truncate_value(s.value), locked=s.locked, inherited_lock=s.inherited_lock, lock_from=s.lock_from)
        )
    return PolicyContentsResponse(
        policy=header,
        summary=LockSummaryView(total=summary.total, locked=summary.locked, share=summary.share, with_lock_flag=summary.with_lock_flag),
        sections=[SectionView(name=name, settings=items) for name, items in by_section.items()],
        errors=[str(e) for e in (content.get("errors") or [])],
    )
