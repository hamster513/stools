"""Зоны из Host.UF_Zone и их разметка — источник двух слагаемых Impact."""
from __future__ import annotations

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.vm.models import VmHost, VmZone

router = APIRouter(prefix="/zones", tags=["vm"])


class ZoneView(BaseModel):
    name: str
    internet_access: bool
    confidential_data: bool
    marked: bool
    hosts: int


class ZoneUpdate(BaseModel):
    name: str
    internet_access: bool
    confidential_data: bool


@router.get("", response_model=list[ZoneView])
def list_zones(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[ZoneView]:
    counts: dict[str, int] = {
        str(zone): int(n)
        for zone, n in db.execute(select(VmHost.zone, func.count()).group_by(VmHost.zone)).all()
    }
    rows = db.execute(select(VmZone).order_by(VmZone.marked, VmZone.name)).scalars().all()
    return [
        ZoneView(
            name=z.name,
            internet_access=z.internet_access,
            confidential_data=z.confidential_data,
            marked=z.marked,
            hosts=int(counts.get(z.name, 0)),
        )
        for z in rows
    ]


@router.put("", status_code=status.HTTP_204_NO_CONTENT)
def put_zones(
    payload: list[ZoneUpdate],
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> None:
    """Сохранить разметку. Пересчёт риска — отдельной задачей
    (`POST /recalculate`), чтобы человек мог разметить десять зон
    и пересчитать один раз."""
    for item in payload:
        zone = db.get(VmZone, item.name)
        if zone is None:
            zone = VmZone(name=item.name)
            db.add(zone)
        zone.internet_access = item.internet_access
        zone.confidential_data = item.confidential_data
        zone.marked = True
    db.commit()
