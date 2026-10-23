"""Сети: CIDR, зона из справочника, площадка, владелец, VLAN, теги; привязка активов."""
from __future__ import annotations

import datetime as dt
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.assets.models import Network
from api.modules.assets.services.networks import (
    NetworkConflict,
    NetworkNotFound,
    all_network_stats,
    create_network,
    delete_network,
    get_network,
    network_stats,
    normalize_cidr,
    update_network,
)
from api.platform.export import Column, export_response

router = APIRouter(prefix="/networks", tags=["assets"])

def _tags(value: list[str] | None) -> list[str] | None:
    return None if value is None else list(dict.fromkeys(t.strip() for t in value if t.strip()))


class NetworkIn(BaseModel):
    cidr: str = Field(max_length=64)
    title: str = Field(default="", max_length=255)
    description: str = Field(default="", max_length=4000)
    #: Имя из справочника зон; пусто — без зоны. Указанная группа — выбор человека (`manual`).
    zone: str | None = None
    #: rules — группу назначают правила (сеть возвращается под них); manual — закрепить группу.
    zone_mode: Literal["manual", "rules"] | None = None
    site: str = Field(default="", max_length=255)
    owner: str = Field(default="", max_length=255)
    vlan: int | None = Field(default=None, ge=1, le=4094)
    tags: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("cidr")
    @classmethod
    def check_cidr(cls, value: str | None) -> str | None:
        return None if value is None else normalize_cidr(value)

    @field_validator("zone")
    @classmethod
    def check_zone(cls, value: str | None) -> str | None:
        return (value or "").strip() or None

    @field_validator("tags")
    @classmethod
    def check_tags(cls, value: list[str] | None) -> list[str] | None:
        return _tags(value)


class NetworkUpdate(NetworkIn):
    """PUT: меняются только переданные поля; явный null у поля, где он не имеет смысла, — 422."""

    cidr: str | None = Field(default=None, max_length=64)  # type: ignore[assignment]
    title: str | None = Field(default=None, max_length=255)  # type: ignore[assignment]
    description: str | None = Field(default=None, max_length=4000)  # type: ignore[assignment]
    site: str | None = Field(default=None, max_length=255)  # type: ignore[assignment]
    owner: str | None = Field(default=None, max_length=255)  # type: ignore[assignment]
    tags: list[str] | None = Field(default=None, max_length=50)  # type: ignore[assignment]

    def changes(self) -> dict[str, Any]:
        data = self.model_dump(include=self.model_fields_set)
        nullable = {"zone", "vlan", "zone_mode"}
        for name, value in data.items():
            if value is None and name not in nullable:
                raise ValueError(f"поле {name} не может быть пустым")
        return data


class NetworkStats(BaseModel):
    assets: int


class NetworkView(BaseModel):
    id: int
    cidr: str
    title: str
    description: str
    zone: str | None
    #: Откуда группа: manual | rule | racktables | "" (не назначена).
    zone_source: str
    zone_rule_id: int | None
    site: str
    owner: str
    vlan: int | None
    tags: list[str]
    #: Пусто — описана вручную; racktables — создана задачей RackTables (название, описание, VLAN и теги обновляет она).
    origin: str
    created_at: dt.datetime
    updated_at: dt.datetime
    stats: NetworkStats


def _view(n: Network, stats: dict[str, Any]) -> NetworkView:
    return NetworkView(
        id=n.id, cidr=n.cidr, title=n.title, description=n.description, zone=n.zone, zone_source=n.zone_source,
        zone_rule_id=n.zone_rule_id, site=n.site, owner=n.owner, vlan=n.vlan, tags=list(n.tags or []),
        origin=n.origin, created_at=n.created_at, updated_at=n.updated_at, stats=NetworkStats(**stats),
    )


def _one(db: Session, n: Network) -> NetworkView:
    return _view(n, network_stats(db, n))


def _errors(fn: Any, *args: Any) -> Any:
    try:
        return fn(*args)
    except NetworkNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from None
    except NetworkConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from None


@router.get("", response_model=list[NetworkView])
def list_networks(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[NetworkView]:
    networks = list(db.execute(select(Network).order_by(Network.cidr)).scalars())
    stats = all_network_stats(db, networks)
    return [_view(n, stats[n.id]) for n in networks]


@router.post("", response_model=NetworkView, status_code=status.HTTP_201_CREATED)
def post_network(payload: NetworkIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> NetworkView:
    network = _errors(create_network, db, payload.model_dump())
    db.commit()
    return _one(db, network)


EXPORT_COLUMNS = [
    Column("cidr", "CIDR"), Column("title", "Название"), Column("zone", "Зона"), Column("site", "Площадка"),
    Column("assets", "Активов"),
]


@router.get("/export")
def export_networks(
    fmt: str = Query(default="csv", alias="format"), db: Session = Depends(get_db), user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    """Все сети в порядке таблицы (у списка фильтров нет); объявлена до `/{network_id}`."""
    rows = [
        {"cidr": v.cidr, "title": (v.title or "—") + (f" · VLAN {v.vlan}" if v.vlan is not None else ""), "zone": v.zone,
         "site": v.site or None, "assets": v.stats.assets}
        for v in list_networks(db=db, _user=user)
    ]
    return export_response(fmt, EXPORT_COLUMNS, rows, module="assets", name="networks")


@router.get("/{network_id}", response_model=NetworkView)
def get_one(network_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> NetworkView:
    network = _errors(get_network, db, network_id)
    return _one(db, network)


@router.put("/{network_id}", response_model=NetworkView)
def put_network(network_id: int, payload: NetworkUpdate, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> NetworkView:
    network = _errors(get_network, db, network_id)
    _errors(update_network, db, network, _errors(payload.changes))
    db.commit()
    return _one(db, network)


@router.delete("/{network_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_network(network_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> Response:
    network = _errors(get_network, db, network_id)
    delete_network(db, network)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
