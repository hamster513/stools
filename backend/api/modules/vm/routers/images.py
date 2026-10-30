"""Образы контейнеров: список, карточка образа, его находки, расчёт риска находки, экспорт.

Только чтение: данные приходят синхронизацией с Harbor (`routers/harbor.py`).
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.vm.core.harbor import is_cve
from api.modules.vm.core.risk import explain
from api.modules.vm.core.weights import Levels
from api.modules.vm.models import VmCve, VmImage, VmRefState
from api.modules.vm.services import images_query as q
from api.modules.vm.services.harbor_sync import last_sync
from api.modules.vm.services.risk_view import cve_inputs, risk_view
from api.modules.vm.services.settings import load_settings
from api.platform.export import Column, export_response
from api.platform.filters import QueryList, multi

router = APIRouter(tags=["vm"])

MAX_LIMIT = 1000


def _levels(db: Session) -> Levels:
    return load_settings(db).weights.levels


def _image_filters(
    q_: str | None = Query(default=None, alias="q"),
    project: QueryList = None,
    scan_status: QueryList = None,
    level: QueryList = None,
    trivy: QueryList = None,
    db: Session = Depends(get_db),
) -> q.ImageFilters:
    """Фасеты `project, scan_status, level, trivy` — повтором ключа; `level=none` — образы без риска;
    `trivy=critical|high` — есть хотя бы одна такая находка."""
    return q.ImageFilters(q_, multi(project), multi(scan_status), multi(level), multi(trivy), None, _levels(db))


def _export_filters(
    f: q.ImageFilters = Depends(_image_filters),
    image_id: int | None = None,
) -> q.ImageFilters:
    f.image_id = image_id
    return f


def _check_sort(sort: str, allowed: dict[str, Any]) -> None:
    if sort not in allowed:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="неизвестная сортировка")


def _image(db: Session, image_id: int) -> VmImage:
    image = db.get(VmImage, image_id)
    if image is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="образ не найден")
    return image


class ImagesResponse(BaseModel):
    #: Только у первой страницы (`offset=0`), как и фасеты.
    total: int | None
    items: list[dict[str, Any]]
    facets: dict[str, dict[str, int]] | None = None


@router.get("/images", response_model=ImagesResponse)
def list_images(
    f: q.ImageFilters = Depends(_image_filters),
    sort: str = Query(default="risk_desc"),
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> ImagesResponse:
    _check_sort(sort, q.IMAGE_SORTS)
    items = q.page_images(db, f, sort, limit, offset)
    if offset > 0:
        return ImagesResponse(total=None, items=items, facets=None)
    return ImagesResponse(total=q.count_images(db, f), items=items, facets=q.image_facets(db, f))


EXPORT_COLUMNS = [
    Column("image", "Образ"),
    Column("platform", "Платформа"),
    Column("tags", "Теги"),
    Column("cve_id", "CVE"),
    Column("package", "Пакет"),
    Column("installed_version", "Установлена"),
    Column("fixed_version", "Исправлена"),
    Column("trivy_severity", "Trivy"),
    Column("trivy_cvss", "CVSS Trivy"),
    Column("risk", "Риск"),
    Column("level", "Уровень"),
    Column("epss", "EPSS"),
    Column("kev", "KEV"),
    Column("scan_status", "Статус скана"),
    Column("scanned_at", "Дата скана"),
]


# Раньше `/images/{image_id}`: иначе `export` разбирался бы как id.
@router.get("/images/export")
def export_images(
    f: q.ImageFilters = Depends(_export_filters),
    sort: str = Query(default="risk_desc"),
    fmt: str = Query(default="csv", alias="format"),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    """CSV (по умолчанию) или XLSX. Фильтры — как у списка образов, плюс `image_id`; строка —
    образ × находка (образ без находок — одна строка). Имена образов, теги и версии приходят
    из Harbor, в CSV они проходят `csv_safe`."""
    _check_sort(sort, q.IMAGE_SORTS)

    def rows() -> Iterator[dict[str, Any]]:
        yield from q.iter_export_rows(db, f, sort)

    return export_response(fmt, EXPORT_COLUMNS, rows(), module="vm", name="images")


@router.get("/images/{image_id}")
def image_detail(
    image_id: int,
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    image = _image(db, image_id)
    sync = last_sync(db)
    return {**q.image_item(image, _levels(db)), "last_sync_at": sync.finished_at if sync else None}


def _vuln_filters(
    image_id: int,
    q_: str | None = Query(default=None, alias="q"),
    severity: QueryList = None,
    level: QueryList = None,
    fixed: Literal["yes", "no"] | None = None,
    db: Session = Depends(get_db),
) -> q.VulnFilters:
    sev = multi(severity)
    return q.VulnFilters(
        image_id, q_, frozenset(s.lower() for s in sev) if sev else None, multi(level),
        None if fixed is None else fixed == "yes", _levels(db),
    )


class VulnsResponse(BaseModel):
    total: int | None
    items: list[dict[str, Any]]
    facets: dict[str, dict[str, int]] | None = None


@router.get("/images/{image_id}/vulns", response_model=VulnsResponse)
def image_vulns(
    f: q.VulnFilters = Depends(_vuln_filters),
    sort: str = Query(default="risk_desc"),
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> VulnsResponse:
    _check_sort(sort, q.VULN_SORTS)
    _image(db, f.image_id)
    items = q.page_vulns(db, f, sort, limit, offset)
    if offset > 0:
        return VulnsResponse(total=None, items=items, facets=None)
    return VulnsResponse(total=q.count_vulns(db, f), items=items, facets=q.vuln_facets(db, f))


@router.get("/images/{image_id}/vulns/{cve_id}")
def image_risk_card(
    image_id: int,
    cve_id: str,
    package: str = Query(),
    installed_version: str = Query(default=""),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Находка образа и расчёт её риска. Находка — (идентификатор, пакет, версия): один CVE
    бывает в нескольких пакетах. Для не-CVE (GHSA-…) и CVE вне витрины расчёта нет — `factors: null`."""
    image = _image(db, image_id)
    vuln_id = cve_id.upper() if is_cve(cve_id) else cve_id
    row = q.find_vuln(db, image_id, vuln_id, package, installed_version)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="находка не найдена")
    settings = load_settings(db)
    levels = settings.weights.levels
    factors = None
    cve = db.get(VmCve, vuln_id) if is_cve(vuln_id) else None
    if cve is not None:
        # Расчёт для образа: критичности, зоны и интернета нет — V базовая (`scoring.image_value`).
        # «Внутри, без интернета и конфиденциальности» для образа — условие формулы, а не подстановка
        # за неразмеченную зону: `zone_marked=True`.
        e = explain(
            cve_inputs(cve, kev_loaded=db.get(VmRefState, "kev") is not None),
            None, internet=False, confidential=False, zone_marked=True, w=settings.weights,
        )
        # Пара ещё без риска (до пересчёта) — показываем расчёт.
        factors = risk_view(e, settings, row.risk if row.risk is not None else e.score,
                            row.risk_raw if row.risk_raw is not None else e.raw)
    return {
        "image": q.image_item(image, levels),
        "vuln": q.vuln_item(row, levels),
        "factors": factors,
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{vuln_id}" if is_cve(vuln_id) else None,
    }
