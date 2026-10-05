"""Вкладка «Настройки» политики: настройки по компонентам защиты человеческим языком (словарь продукта),
нераспознанное — в «Прочее» в техническом виде. Содержимое читается из сохранённого файла выгрузки."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.ksc.core.dictionary import DICTIONARIES, component_enabled, describe
from api.modules.ksc.core.policy_contents import Setting, flat_settings, truncate_value
from api.modules.ksc.routers.policy_list import _index, _policy, _snapshot
from api.settings import Settings, get_settings

router = APIRouter(tags=["ksc"])


class DescribedSetting(BaseModel):
    section: str
    path: str
    title: str
    value: str
    #: Значение как есть (JSON-текст, длиннее 200 знаков обрезается).
    raw: str
    locked: bool | None = None
    #: False — подпись значения не подтверждена (показан «код N»).
    verified: bool


class ComponentGroup(BaseModel):
    component: str
    title: str
    #: None — у компонента нет признака «включён» или его нет в политике.
    enabled: bool | None = None
    settings: list[DescribedSetting]


class OtherSetting(BaseModel):
    section: str
    path: str
    value: str
    locked: bool | None = None


class PolicySettingsResponse(BaseModel):
    #: Для продукта есть словарь; False — все настройки в `other`.
    described: bool
    known: int
    total: int
    groups: list[ComponentGroup]
    other: list[OtherSetting]


def _other(settings: list[Setting]) -> list[OtherSetting]:
    return [OtherSetting(section=s.section, path=s.path, value=truncate_value(s.value), locked=s.locked) for s in settings]


@router.get("/snapshots/{snapshot_id}/policies/{policy_id}/settings", response_model=PolicySettingsResponse)
def get_policy_settings(
    snapshot_id: int,
    policy_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> PolicySettingsResponse:
    snap = _snapshot(db, snapshot_id, settings)
    p = _policy(db, snapshot_id, policy_id)
    content = _index(snap, settings).export.policy_contents.get(str(policy_id)) or {}
    sections = content.get("sections") or {}
    result = describe(p.product, sections)
    if result is None:
        other = flat_settings(sections)
        return PolicySettingsResponse(described=False, known=0, total=len(other), groups=[], other=_other(other))
    known, rest = result
    groups = []
    for component, title in DICTIONARIES[p.product].components.items():
        items = [
            DescribedSetting(section=k.section, path=k.path, title=k.title, value=k.value, raw=k.raw, locked=k.locked, verified=k.verified)
            for k in known if k.component == component
        ]
        if items:
            groups.append(ComponentGroup(component=component, title=title, enabled=component_enabled(p.product, sections, component), settings=items))
    return PolicySettingsResponse(
        described=True, known=len(known), total=len(known) + len(rest), groups=groups, other=_other(rest),
    )
