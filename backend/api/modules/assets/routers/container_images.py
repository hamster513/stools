"""Read-only image catalogue: Harbor artifacts and MP VM runtime observations."""
from __future__ import annotations

import json
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import Integer, func, literal, select, union_all
from sqlalchemy.orm import Session
from sqlalchemy.sql import Subquery

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.assets.services.image_origins import (
    ORIGIN_LABELS,
    corporate_registries,
    harbor_origin,
    origin_for_references,
)
from api.modules.vm.docker_models import VmDockerImage, VmDockerSnapshot
from api.modules.vm.models import VmImage
from api.platform.export import Column, export_response
from api.platform.filters import QueryList, multi

router = APIRouter()
Source = Literal["harbor", "mp_vm"]
State = Literal["running", "stopped", "unused", "unknown"]


def _catalog() -> Subquery:
    h, d = VmImage, VmDockerImage
    return union_all(
        select(h.id, literal("harbor").label("source"), (h.project + "/" + h.repository).label("title"),
               h.digest.label("image_id"), h.platform, h.size, h.synced_at.label("collected_at"),
               literal("unknown").label("status"), literal(None, Integer).label("host_count"),
               literal(None, Integer).label("container_count"),
               (h.project + "/" + h.repository + " " + h.tags + " " + h.digest).label("search_text")),
        select(d.id, literal("mp_vm"), d.title, d.image_id, d.platform, literal(None, Integer),
               d.collected_at, d.status, d.host_count, d.container_count, d.search_text),
    ).subquery()


def _tags(raw: str) -> list[str]:
    value = json.loads(raw or "[]")
    return value if isinstance(value, list) else []


SOURCE_LABELS = {"harbor": "Harbor", "mp_vm": "MaxPatrol VM"}
STATUS_LABELS = {"running": "Есть запущенные", "stopped": "Контейнеры не запущены",
                 "unused": "Без контейнеров", "unknown": "Нет данных о запуске"}
EXPORT_COLUMNS = [Column("title", "Образ"), Column("tags", "Теги"), Column("source", "Источник"),
                  Column("registry_origin", "Реестр"), Column("registries", "Адреса реестров"),
                  Column("external_registries", "Внешние реестры"), Column("status", "Использование"), Column("host_count", "Хостов"),
                  Column("container_count", "Контейнеров"), Column("image_id", "Хеш / ID"),
                  Column("platform", "Платформа"), Column("size", "Размер, байт"),
                  Column("collected_at", "Получено")]


def _filters(
    q: str = Query(default="", max_length=200),
    source: QueryList = None,
    status: QueryList = None,
    image_id: int | None = Query(default=None, ge=1),
) -> dict[str, Any]:
    sources, states = multi(source), multi(status)
    if sources and not sources <= SOURCE_LABELS.keys():
        raise HTTPException(422, "Неизвестный источник")
    if states and not states <= STATUS_LABELS.keys():
        raise HTTPException(422, "Неизвестное состояние")
    if image_id is not None and (not sources or len(sources) != 1):
        raise HTTPException(422, "Для выбора образа укажите один источник")
    return {"q": q, "source": sources, "status": states, "image_id": image_id}


def _conditions(catalogue: Subquery, filters: dict[str, Any], skip: str = "") -> list[Any]:
    clauses: list[Any] = []
    for key in ("source", "status"):
        # Exact IDs are scoped to one source, including while computing facets.
        if filters[key] and (key != skip or filters["image_id"] is not None and key == "source"):
            clauses.append(catalogue.c[key].in_(filters[key]))
    if filters["image_id"] is not None:
        clauses.append(catalogue.c.id == filters["image_id"])
    if filters["q"].strip():
        escaped = filters["q"].strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clauses.append(catalogue.c.search_text.ilike(f"%{escaped}%", escape="\\"))
    return clauses


def _items(db: Session, catalogue: Subquery, filters: dict[str, Any], limit: int | None, offset: int = 0) -> list[dict[str, Any]]:
    rows = db.execute(select(catalogue).where(*_conditions(catalogue, filters)).order_by(
        catalogue.c.title, catalogue.c.source, catalogue.c.id,
    ).limit(limit).offset(offset)).mappings().all()
    tags = {}
    origins = {}
    corporate = corporate_registries(db)
    for src, model in (("harbor", VmImage), ("mp_vm", VmDockerImage)):
        ids = [row["id"] for row in rows if row["source"] == src]
        # Bound IN lists even for a full export.
        for start in range(0, len(ids), 1000):
            reference = VmImage.registry_url if src == "harbor" else VmDockerImage.details["references"]
            for row_id, values, refs in db.execute(select(model.id, model.tags, reference).where(model.id.in_(ids[start:start + 1000]))):
                tags[(src, row_id)] = _tags(values) if src == "harbor" else values
                origins[(src, row_id)] = harbor_origin(refs) if src == "harbor" else origin_for_references(refs, corporate)
    return [{**{key: value for key, value in row.items() if key != "search_text"},
             "tags": tags.get((row["source"], row["id"]), []), **origins.get((row["source"], row["id"]), origin_for_references(None, corporate))} for row in rows]


@router.get("/container-images")
def list_images(
    filters: dict[str, Any] = Depends(_filters),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    catalogue = _catalog()
    total = db.scalar(select(func.count()).select_from(catalogue).where(*_conditions(catalogue, filters)))
    facets = None
    if offset == 0:
        facets = {}
        for key, labels in (("source", SOURCE_LABELS), ("status", STATUS_LABELS)):
            counts = {value: count for value, count in db.execute(select(catalogue.c[key], func.count()).where(
                *_conditions(catalogue, filters, skip=key),
            ).group_by(catalogue.c[key])).all()}
            facets[key] = {value: counts.get(value, 0) for value in labels}
    snapshot = db.get(VmDockerSnapshot, 1)
    return {"items": _items(db, catalogue, filters, limit, offset), "total": total, "facets": facets,
            "limit": limit, "offset": offset,
            "mp_vm": {"collected_at": snapshot.collected_at, "attempted_at": snapshot.attempted_at,
                      "error": snapshot.error} if snapshot else None}


@router.get("/container-images/export")
def export_images(
    filters: dict[str, Any] = Depends(_filters),
    fmt: str = Query(default="csv", alias="format"),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    items = _items(db, _catalog(), filters, limit=None)
    for item in items:
        item["tags"] = ", ".join(item["tags"])
        item["registry_origin"] = ORIGIN_LABELS[item["registry_origin"]]
        item["registries"] = ", ".join(item["registries"])
        item["external_registries"] = ", ".join(item["external_registries"])
        item["status"] = "В реестре" if item["source"] == "harbor" else STATUS_LABELS[item["status"]]
        item["source"] = SOURCE_LABELS[item["source"]]
    return export_response(fmt, EXPORT_COLUMNS, items, module="assets", name="container-images")


@router.get("/container-images/{source}/{image_id}")
def image_detail(
    source: Source, image_id: int,
    db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    if source == "mp_vm":
        row = db.get(VmDockerImage, image_id)
        if row is None:
            raise HTTPException(404, "Образ не найден")
        snapshot = db.get(VmDockerSnapshot, 1)
        return {**row.details, "source": source, "collected_at": row.collected_at,
                "source_address": snapshot.source_address if snapshot else "", "size": None,
                "hash_kind": "Image.ID (MaxPatrol VM)",
                **origin_for_references(row.details.get("references"), corporate_registries(db))}
    image = db.get(VmImage, image_id)
    if image is None:
        raise HTTPException(404, "Образ не найден")
    return {**harbor_origin(image.registry_url), "source": source, "source_address": image.registry_url, "image_id": image.digest,
            "hash_kind": "Digest артефакта Harbor", "size": image.size, "status": "unknown",
            "collected_at": image.synced_at, "pushed_at": image.pushed_at,
            "platforms": [image.platform] if image.platform else [], "hosts": [],
            "references": [{"registry": "", "repo": image.project + "/" + image.repository, "tag": t}
                           for t in (_tags(image.tags) or [""])],
            "scan_status": image.scan_status, "scanned_at": image.scanned_at, "sync_error": image.sync_error}
