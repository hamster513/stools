"""Сети: CIDR, зона из справочника, площадка, владелец, VLAN, теги; привязка активов. Список — по страницам
с поиском и фасетами, выгрузка — по тем же фильтрам, карточка — с правилом группы и объемлющими сетями."""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.assets.routers.assets import EXPORT_ALL, MAX_LIMIT, _check
from api.modules.assets.services.networks import (
    ORIGINS,
    PLACEMENTS,
    ZONE_SOURCES,
    NetworkConflict,
    NetworkNotFound,
    create_network,
    delete_network,
    get_network,
    list_networks,
    network_detail,
    networks_for_export,
    normalize_cidr,
    update_network,
)
from api.platform.export import Column, export_response
from api.platform.filters import QueryList, multi

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


def _errors(fn: Any, *args: Any) -> Any:
    try:
        return fn(*args)
    except NetworkNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from None
    except NetworkConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from None


def _filters(
    q: str | None = Query(default=None, max_length=200),
    zone: QueryList = None,
    placement: QueryList = None,
    zone_source: QueryList = None,
    origin: QueryList = None,
) -> dict[str, Any]:
    """Фильтры списка и выгрузки; многозначные — повтором ключа, `-` — не задано."""
    picked = {"zone": multi(zone), "placement": multi(placement), "zone_source": multi(zone_source), "origin": multi(origin)}
    _check(picked["placement"], PLACEMENTS)
    _check(picked["zone_source"], ZONE_SOURCES)
    _check(picked["origin"], ORIGINS)
    return {"q": q, **picked}


@router.get("")
def get_networks(
    filters: dict[str, Any] = Depends(_filters),
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    body = list_networks(db, **filters, limit=limit, offset=offset)
    return {**body, "facets": body["facets"] if offset == 0 else None}


@router.post("", status_code=status.HTTP_201_CREATED)
def post_network(payload: NetworkIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    network = _errors(create_network, db, payload.model_dump())
    db.commit()
    return network_detail(db, network.id)


#: Подписи расположения — как на экране.
PLACEMENT_TITLES = {"internal": "внутренняя", "dmz": "DMZ", "external": "внешняя"}

EXPORT_COLUMNS = [
    Column("cidr", "CIDR"), Column("title", "Название"), Column("zone", "Группа"), Column("placement", "Расположение"),
    Column("vlan", "VLAN"), Column("site", "Площадка"), Column("tags", "Теги"), Column("assets", "Активов"),
]


@router.get("/export")
def export_networks(
    filters: dict[str, Any] = Depends(_filters),
    fmt: str = Query(default="csv", alias="format"),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    """Сети под фильтрами списка, в его порядке; объявлена до `/{network_id}`. Теги — явные и унаследованные."""
    rows = [
        {"cidr": n["cidr"], "title": n["title"] or None, "zone": n["zone"], "placement": PLACEMENT_TITLES.get(n["placement"]),
         "vlan": n["vlan"], "site": n["site"] or None, "tags": ", ".join(dict.fromkeys([*n["tags"], *n["implicit_tags"]])) or None,
         "assets": n["assets"]}
        for n in networks_for_export(db, **filters, limit=EXPORT_ALL)
    ]
    return export_response(fmt, EXPORT_COLUMNS, rows, module="assets", name="networks")


@router.get("/{network_id}")
def get_one(network_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    return dict(_errors(network_detail, db, network_id))


@router.put("/{network_id}")
def put_network(network_id: int, payload: NetworkUpdate, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    network = _errors(get_network, db, network_id)
    _errors(update_network, db, network, _errors(payload.changes))
    db.commit()
    return network_detail(db, network.id)


@router.delete("/{network_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_network(network_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> Response:
    network = _errors(get_network, db, network_id)
    delete_network(db, network)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
