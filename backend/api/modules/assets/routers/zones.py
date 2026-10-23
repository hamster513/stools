"""Справочник зон сетей (в интерфейсе — группы сетей): предустановленные зоны и их признаки кладёт
миграция, дальше справочник правят руками."""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.assets.services.networks import (
    NetworkConflict,
    NetworkNotFound,
    create_zone,
    delete_zone,
    list_zones,
    update_zone,
    zone_view,
)

router = APIRouter(prefix="/zones", tags=["assets"])

#: Расположение группы: внутренняя, DMZ, внешняя; пусто — не задано.
Placement = Literal["internal", "dmz", "external", ""]


class ZoneIn(BaseModel):
    name: str = Field(max_length=64)
    title: str = Field(default="", max_length=255)
    description: str = Field(default="", max_length=4000)
    placement: Placement = ""
    internet_facing: bool = False
    confidential: bool = False

    @field_validator("name")
    @classmethod
    def check_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("имя зоны не может быть пустым")
        if "/" in value:
            raise ValueError("в имени зоны не может быть «/»")
        return value


class ZonePatch(BaseModel):
    """PATCH: меняются только переданные поля; null — 422."""

    title: str | None = Field(default=None, max_length=255)
    description: str | None = Field(default=None, max_length=4000)
    placement: Placement | None = None
    internet_facing: bool | None = None
    confidential: bool | None = None

    def changes(self) -> dict[str, Any]:
        data = self.model_dump(include=self.model_fields_set)
        for name, value in data.items():
            if value is None:
                raise ValueError(f"поле {name} не может быть пустым")
        return {k: v.strip() if isinstance(v, str) and k != "placement" else v for k, v in data.items()}


class ZoneView(BaseModel):
    name: str
    title: str
    description: str
    placement: str
    internet_facing: bool
    #: Конфиденциальные данные в сетях группы.
    confidential: bool
    #: Сколько сетей ссылается на зону: пока не ноль, удалить её нельзя.
    networks: int


@router.get("", response_model=list[ZoneView])
def get_zones(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[dict[str, Any]]:
    return list_zones(db)


@router.post("", response_model=ZoneView, status_code=status.HTTP_201_CREATED)
def post_zone(payload: ZoneIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> ZoneView:
    try:
        zone = create_zone(
            db, payload.name, payload.title.strip(), payload.description.strip(),
            placement=payload.placement, internet_facing=payload.internet_facing, confidential=payload.confidential,
        )
    except NetworkConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None
    db.commit()
    return ZoneView(**zone_view(zone, 0))


@router.patch("/{name}", response_model=ZoneView)
def patch_zone(name: str, payload: ZonePatch, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    try:
        view = update_zone(db, name, payload.changes())
    except NetworkNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from None
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from None
    db.commit()
    return view


@router.delete("/{name}", status_code=status.HTTP_204_NO_CONTENT)
def remove_zone(name: str, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> Response:
    try:
        delete_zone(db, name)
    except NetworkNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from None
    except NetworkConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
