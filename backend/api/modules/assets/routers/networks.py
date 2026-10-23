"""Сети: CIDR, зона из справочника, площадка, владелец, настройки сканирования.

Запуск скана и правка расписания — `routers/scan.py`; здесь описание сети, привязка активов
и расписание в составе сети (для таблицы).
"""
from __future__ import annotations

import datetime as dt
from typing import Any, Literal
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.assets.models import DEFAULT_PORTS, Network
from api.modules.assets.services.networks import (
    NetworkConflict,
    NetworkNotFound,
    all_network_stats,
    create_network,
    delete_network,
    estimated_seconds,
    get_network,
    network_stats,
    normalize_cidr,
    normalize_exclude,
    update_network,
)
from api.platform.export import Column, export_response
from api.platform.schedule_views import ScheduleView, schedule_view
from api.platform.scheduler import PlatformSchedule
from api.settings import get_settings

router = APIRouter(prefix="/networks", tags=["assets"])

MAX_PORTS = 64


def _ports(value: list[int] | None) -> list[int] | None:
    if value is None:
        return None
    if len(value) > MAX_PORTS:
        raise ValueError(f"портов не больше {MAX_PORTS}")
    if any(not 1 <= p <= 65535 for p in value):
        raise ValueError("порт — число от 1 до 65535")
    return list(dict.fromkeys(value))


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
    scan_enabled: bool = False
    ports: list[int] = Field(default_factory=lambda: list(DEFAULT_PORTS))
    exclude: list[str] = Field(default_factory=list, max_length=256)
    concurrency: int = Field(default=64, ge=1, le=256)
    icmp_timeout_ms: int = Field(default=1000, ge=50, le=10000)
    tcp_timeout_ms: int = Field(default=2000, ge=50, le=30000)
    rate_per_s: int = Field(default=500, ge=10, le=5000)

    @field_validator("cidr")
    @classmethod
    def check_cidr(cls, value: str | None) -> str | None:
        return None if value is None else normalize_cidr(value)

    @field_validator("zone")
    @classmethod
    def check_zone(cls, value: str | None) -> str | None:
        return (value or "").strip() or None

    @field_validator("ports")
    @classmethod
    def check_ports(cls, value: list[int] | None) -> list[int] | None:
        return _ports(value)

    @field_validator("exclude")
    @classmethod
    def check_exclude(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else list(dict.fromkeys(normalize_exclude(v) for v in value if v.strip()))

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
    scan_enabled: bool | None = None  # type: ignore[assignment]
    ports: list[int] | None = None  # type: ignore[assignment]
    exclude: list[str] | None = Field(default=None, max_length=256)  # type: ignore[assignment]
    concurrency: int | None = Field(default=None, ge=1, le=256)  # type: ignore[assignment]
    icmp_timeout_ms: int | None = Field(default=None, ge=50, le=10000)  # type: ignore[assignment]
    tcp_timeout_ms: int | None = Field(default=None, ge=50, le=30000)  # type: ignore[assignment]
    rate_per_s: int | None = Field(default=None, ge=10, le=5000)  # type: ignore[assignment]

    def changes(self) -> dict[str, Any]:
        data = self.model_dump(include=self.model_fields_set)
        nullable = {"zone", "vlan", "zone_mode"}
        for name, value in data.items():
            if value is None and name not in nullable:
                raise ValueError(f"поле {name} не может быть пустым")
        return data


class NetworkStats(BaseModel):
    assets: int
    #: Живых при последнем скане; None — сеть ещё не сканировали.
    alive_last_scan: int | None
    unknown_hosts: int


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
    scan_enabled: bool
    ports: list[int]
    exclude: list[str]
    concurrency: int
    icmp_timeout_ms: int
    tcp_timeout_ms: int
    rate_per_s: int
    #: Секунд на скан, если никто не ответит; None — сеть сканеру не по силам.
    estimated_seconds: int | None
    schedule_id: int | None
    last_scan_at: dt.datetime | None
    last_scan_alive: int | None
    #: False — последний скан шёл в режиме «только порты»; None — сеть не сканировали.
    last_scan_icmp: bool | None
    #: Пусто — описана вручную; racktables — создана задачей RackTables (название, описание, VLAN и теги обновляет она).
    origin: str
    created_at: dt.datetime
    updated_at: dt.datetime
    stats: NetworkStats
    schedule: ScheduleView | None


def _schedules(db: Session, networks: list[Network]) -> dict[int, PlatformSchedule]:
    ids = [n.schedule_id for n in networks if n.schedule_id is not None]
    if not ids:
        return {}
    return {s.id: s for s in db.execute(select(PlatformSchedule).where(PlatformSchedule.id.in_(ids))).scalars()}


def _view(n: Network, stats: dict[str, Any], schedules: dict[int, PlatformSchedule]) -> NetworkView:
    sched = schedules.get(n.schedule_id) if n.schedule_id is not None else None
    return NetworkView(
        id=n.id, cidr=n.cidr, title=n.title, description=n.description, zone=n.zone, zone_source=n.zone_source,
        zone_rule_id=n.zone_rule_id, site=n.site, owner=n.owner, vlan=n.vlan,
        tags=list(n.tags or []), scan_enabled=n.scan_enabled, ports=list(n.ports or []), exclude=list(n.exclude or []),
        concurrency=n.concurrency, icmp_timeout_ms=n.icmp_timeout_ms, tcp_timeout_ms=n.tcp_timeout_ms,
        rate_per_s=n.rate_per_s, estimated_seconds=estimated_seconds(n), schedule_id=n.schedule_id,
        last_scan_at=n.last_scan_at, last_scan_alive=n.last_scan_alive, last_scan_icmp=n.last_scan_icmp, origin=n.origin, created_at=n.created_at, updated_at=n.updated_at,
        stats=NetworkStats(**stats), schedule=schedule_view(sched) if sched is not None else None,
    )


def _one(db: Session, n: Network) -> NetworkView:
    return _view(n, network_stats(db, n), _schedules(db, [n]))


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
    schedules = _schedules(db, networks)
    return [_view(n, stats[n.id], schedules) for n in networks]


@router.post("", response_model=NetworkView, status_code=status.HTTP_201_CREATED)
def post_network(payload: NetworkIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> NetworkView:
    network = _errors(create_network, db, payload.model_dump())
    db.commit()
    return _one(db, network)


EXPORT_COLUMNS = [
    Column("cidr", "CIDR"), Column("title", "Название"), Column("zone", "Зона"), Column("site", "Площадка"),
    Column("assets", "Активов"), Column("alive", "Живых"), Column("scanner_only", "Только сканер"),
    Column("last_scan", "Последний скан"), Column("schedule", "Расписание"),
]


def _schedule_text(v: NetworkView) -> str:
    """Колонка «Расписание» — как на экране (`scheduleText`); время следующего запуска — в поясе STOOLS_TZ."""
    s = v.schedule
    if s is None:
        return "вручную" if v.scan_enabled else "не сканируется"
    every = f"раз в {s.interval_hours // 24} сут" if s.interval_hours % 24 == 0 else f"раз в {s.interval_hours} ч"
    window = f", {s.window_from}–{s.window_to} {s.tz}" if s.window_from and s.window_to else ""
    if not s.enabled:
        return f"выключено ({every}{window})"
    nxt = s.next_run_at.astimezone(ZoneInfo(get_settings().tz)).strftime("%d.%m.%Y %H:%M") if s.next_run_at else "—"
    return f"{every}{window}; следующий {nxt}"


@router.get("/export")
def export_networks(
    fmt: str = Query(default="csv", alias="format"), db: Session = Depends(get_db), user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    """Все сети в порядке таблицы (у списка фильтров нет); объявлена до `/{network_id}`."""
    rows = [
        {"cidr": v.cidr, "title": (v.title or "—") + (f" · VLAN {v.vlan}" if v.vlan is not None else ""), "zone": v.zone,
         "site": v.site or None, "assets": v.stats.assets, "alive": v.stats.alive_last_scan, "scanner_only": v.stats.unknown_hosts,
         "last_scan": v.last_scan_at, "schedule": _schedule_text(v)}
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
