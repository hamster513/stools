"""Справочник зон сетей: предустановленные зоны кладёт миграция, дальше справочник правят руками."""
from __future__ import annotations

from typing import Any

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
)

router = APIRouter(prefix="/zones", tags=["assets"])


class ZoneIn(BaseModel):
    name: str = Field(max_length=64)
    title: str = Field(default="", max_length=255)
    description: str = Field(default="", max_length=4000)

    @field_validator("name")
    @classmethod
    def check_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("имя зоны не может быть пустым")
        if "/" in value:
            raise ValueError("в имени зоны не может быть «/»")
        return value


class ZoneView(BaseModel):
    name: str
    title: str
    description: str
    #: Сколько сетей ссылается на зону: пока не ноль, удалить её нельзя.
    networks: int


@router.get("", response_model=list[ZoneView])
def get_zones(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[dict[str, Any]]:
    return list_zones(db)


@router.post("", response_model=ZoneView, status_code=status.HTTP_201_CREATED)
def post_zone(payload: ZoneIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> ZoneView:
    try:
        zone = create_zone(db, payload.name, payload.title.strip(), payload.description.strip())
    except NetworkConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None
    db.commit()
    return ZoneView(name=zone.name, title=zone.title, description=zone.description, networks=0)


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
