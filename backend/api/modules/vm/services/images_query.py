"""Выборка образов контейнеров и их находок: фильтры, фасеты, сортировки.

Образов — тысячи, находок — сотни тысяч: список образов считает фасеты тремя
группировками по `vm_image`, список находок одного образа — по его строкам
`vm_image_cve` (ключ начинается с `image_id`). Уровень не хранится: он выводится из
балла по порогам настроек (`load_settings(db).weights.levels`), как у пар хост–CVE;
у образа без пар с риском (`risk_max IS NULL`) и у находки без риска (GHSA, CVE вне
витрины) уровня нет — в фасетах это значение `none`.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Select, case, func, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql import ColumnElement

from api.modules.vm.core.harbor import SEVERITIES, is_cve
from api.modules.vm.core.risk import level as risk_level
from api.modules.vm.core.weights import Levels
from api.modules.vm.models import VmCve, VmImage, VmImageCve
from api.modules.vm.services.query import LEVELS, level_bounds, one_of

#: Значение фасета уровня для образа или находки без риска.
NO_LEVEL = "none"
#: Фильтр `trivy`: «есть хотя бы одна находка такой серьёзности».
TRIVY_FLAGS = ("critical", "high")
DIGEST_SHORT = 12

NAME = func.concat(VmImage.project, "/", VmImage.repository)
_TAIL = [NAME, VmImage.id]

IMAGE_SORTS: dict[str, list[Any]] = {
    "risk_desc": [VmImage.risk_max.desc().nulls_last(), *_TAIL],
    "name": _TAIL,
    "pushed_desc": [VmImage.pushed_at.desc().nulls_last(), *_TAIL],
    "trivy_desc": [
        VmImage.trivy_critical.desc(), VmImage.trivy_high.desc(), VmImage.trivy_medium.desc(),
        VmImage.trivy_low.desc(), VmImage.trivy_unknown.desc(), *_TAIL,
    ],
}

#: Ключ пары целиком: страницы по offset не повторяют и не теряют находок.
_PAIR_KEY = [VmImageCve.cve_id, VmImageCve.package, VmImageCve.installed_version]
_SEVERITY_RANK = case(*[(VmImageCve.trivy_severity == s, i) for i, s in enumerate(SEVERITIES)], else_=len(SEVERITIES))

VULN_SORTS: dict[str, list[Any]] = {
    "risk_desc": [VmImageCve.risk.desc().nulls_last(), *_PAIR_KEY],
    "severity_desc": [_SEVERITY_RANK, VmImageCve.risk.desc().nulls_last(), *_PAIR_KEY],
    "package": [VmImageCve.package, *_PAIR_KEY],
    "cve": _PAIR_KEY,
}


def like(text: str) -> str:
    """Подстрока для `ILIKE ... ESCAPE '\\'`: `%` и `_` в запросе — обычные символы."""
    escaped = text.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _level_condition(col: Any, chosen: frozenset[str], levels: Levels) -> ColumnElement[bool] | None:
    """Отбор по уровню: отрезки балла по порогам и `none` — «балла нет». Неизвестные значения
    пропускаются; фильтр из одних таких не задан."""
    bounds = level_bounds(levels)
    parts = [col.between(*bounds[lvl]) for lvl in sorted(chosen) if lvl in bounds]
    if NO_LEVEL in chosen:
        parts.append(col.is_(None))
    return or_(*parts) if parts else None


def level_of(risk: int | None, levels: Levels) -> str | None:
    return None if risk is None else risk_level(risk, levels)


def _fold_levels(by_risk: dict[int | None, int], levels: Levels) -> dict[str, int]:
    out = dict.fromkeys((NO_LEVEL, *LEVELS), 0)
    for risk, n in by_risk.items():
        out[level_of(risk, levels) or NO_LEVEL] += n
    return out


# ---- Образы ---------------------------------------------------------------------


@dataclass
class ImageFilters:
    q: str | None = None
    project: frozenset[str] | None = None
    scan_status: frozenset[str] | None = None
    level: frozenset[str] | None = None
    trivy: frozenset[str] | None = None
    image_id: int | None = None
    levels: Levels = field(default_factory=Levels)


def image_conditions(f: ImageFilters) -> list[ColumnElement[bool]]:
    conds: list[ColumnElement[bool]] = []
    if f.q and f.q.strip():
        needle = like(f.q)
        # Теги ищутся по JSON-тексту столбца `tags` (с кавычками и запятыми) — для первой версии достаточно.
        conds.append(or_(NAME.ilike(needle, escape="\\"), VmImage.tags.ilike(needle, escape="\\")))
    if f.project is not None:
        conds.append(one_of(VmImage.project, f.project))
    if f.scan_status is not None:
        conds.append(one_of(VmImage.scan_status, f.scan_status))
    if f.level is not None and (cond := _level_condition(VmImage.risk_max, f.level, f.levels)) is not None:
        conds.append(cond)
    flags = [
        VmImage.trivy_critical > 0 if v == "critical" else VmImage.trivy_high > 0
        for v in sorted(f.trivy or ()) if v in TRIVY_FLAGS
    ]
    if flags:
        conds.append(or_(*flags))
    if f.image_id is not None:
        conds.append(VmImage.id == f.image_id)
    return conds


def short_digest(digest: str) -> str:
    """Первые 12 знаков хеша без префикса алгоритма (`sha256:`)."""
    return digest.split(":", 1)[-1][:DIGEST_SHORT]


def parse_tags(text: str | None) -> list[str]:
    try:
        value = json.loads(text or "[]")
    except ValueError:
        return []
    return [str(t) for t in value] if isinstance(value, list) else []


def image_item(img: VmImage, levels: Levels) -> dict[str, Any]:
    return {
        "id": img.id,
        "project": img.project,
        "repository": img.repository,
        "name": f"{img.project}/{img.repository}",
        "platform": img.platform,
        "tags": parse_tags(img.tags),
        "digest_short": short_digest(img.digest),
        "digest": img.digest,
        "size": img.size,
        "pushed_at": img.pushed_at,
        "scan_status": img.scan_status,
        "scanned_at": img.scanned_at,
        "scanner": img.scanner,
        "trivy": {
            "critical": img.trivy_critical,
            "high": img.trivy_high,
            "medium": img.trivy_medium,
            "low": img.trivy_low,
            "unknown": img.trivy_unknown,
            "total": img.trivy_total,
        },
        "risk_max": img.risk_max,
        "level": level_of(img.risk_max, levels),
        "cves_scored": img.cves_scored,
        "sync_error": img.sync_error,
    }


def page_images(db: Session, f: ImageFilters, sort: str, limit: int, offset: int) -> list[dict[str, Any]]:
    stmt = select(VmImage).where(*image_conditions(f)).order_by(*IMAGE_SORTS[sort]).limit(limit).offset(offset)
    return [image_item(img, f.levels) for img in db.scalars(stmt)]


def count_images(db: Session, f: ImageFilters) -> int:
    return int(db.execute(select(func.count()).select_from(VmImage).where(*image_conditions(f))).scalar() or 0)


def _counts(db: Session, expr: Any, conds: list[ColumnElement[bool]]) -> dict[Any, int]:
    stmt = select(expr, func.count()).select_from(VmImage).where(*conds).group_by(expr).order_by(func.count().desc(), expr)
    return {k: int(n) for k, n in db.execute(stmt).all()}


def image_facets(db: Session, f: ImageFilters) -> dict[str, dict[str, int]]:
    """Счётчики по всей выборке с теми же фильтрами, а не по странице."""
    conds = image_conditions(f)
    return {
        "project": {str(k): n for k, n in _counts(db, VmImage.project, conds).items()},
        "scan_status": {str(k): n for k, n in _counts(db, VmImage.scan_status, conds).items()},
        "level": _fold_levels(_counts(db, VmImage.risk_max, conds), f.levels),
    }


# ---- Находки образа -------------------------------------------------------------


@dataclass
class VulnFilters:
    image_id: int
    q: str | None = None
    severity: frozenset[str] | None = None
    level: frozenset[str] | None = None
    #: True — исправление есть, False — нет, None — не важно.
    fixed: bool | None = None
    levels: Levels = field(default_factory=Levels)


def _is_fixed() -> ColumnElement[bool]:
    return (VmImageCve.fixed_version.is_not(None)) & (VmImageCve.fixed_version != "")


def vuln_conditions(f: VulnFilters) -> list[ColumnElement[bool]]:
    conds: list[ColumnElement[bool]] = [VmImageCve.image_id == f.image_id]
    if f.q and f.q.strip():
        needle = like(f.q)
        conds.append(or_(VmImageCve.cve_id.ilike(needle, escape="\\"), VmImageCve.package.ilike(needle, escape="\\")))
    if f.severity is not None:
        conds.append(VmImageCve.trivy_severity.in_(sorted(f.severity)))
    if f.level is not None and (cond := _level_condition(VmImageCve.risk, f.level, f.levels)) is not None:
        conds.append(cond)
    if f.fixed is not None:
        conds.append(_is_fixed() if f.fixed else ~_is_fixed())
    return conds


VULN_COLUMNS = [
    VmImageCve.cve_id,
    VmImageCve.package,
    VmImageCve.installed_version,
    VmImageCve.fixed_version,
    VmImageCve.trivy_severity,
    VmImageCve.trivy_cvss,
    VmImageCve.risk,
    VmImageCve.risk_raw,
    VmImageCve.description,
    VmImageCve.link,
    VmCve.epss,
    VmCve.kev,
    VmCve.cvss,
    VmCve.cvss_source,
]


def vulns_select(columns: list[Any]) -> Select[Any]:
    """Находки и витрина: идентификатор не из витрины (GHSA-…) остаётся без её полей."""
    return select(*columns).select_from(VmImageCve).outerjoin(VmCve, VmCve.cve_id == VmImageCve.cve_id)


def vuln_item(row: Any, levels: Levels) -> dict[str, Any]:
    return {
        "cve_id": row.cve_id,
        "package": row.package,
        "installed_version": row.installed_version,
        "fixed_version": row.fixed_version,
        "trivy_severity": row.trivy_severity,
        "trivy_cvss": row.trivy_cvss,
        "risk": row.risk,
        "level": level_of(row.risk, levels),
        "epss": row.epss,
        # Нет строки в витрине — признака нет, а не «не в KEV».
        "kev": None if row.kev is None else bool(row.kev),
        "cvss": row.cvss,
        "cvss_source": row.cvss_source,
        "description": row.description,
        "link": row.link,
        "is_cve": is_cve(row.cve_id),
    }


def page_vulns(db: Session, f: VulnFilters, sort: str, limit: int, offset: int) -> list[dict[str, Any]]:
    stmt = vulns_select(VULN_COLUMNS).where(*vuln_conditions(f)).order_by(*VULN_SORTS[sort]).limit(limit).offset(offset)
    return [vuln_item(r, f.levels) for r in db.execute(stmt)]


def count_vulns(db: Session, f: VulnFilters) -> int:
    return int(db.execute(select(func.count()).select_from(VmImageCve).where(*vuln_conditions(f))).scalar() or 0)


def vuln_facets(db: Session, f: VulnFilters) -> dict[str, dict[str, int]]:
    conds = vuln_conditions(f)

    def counts(expr: Any) -> dict[Any, int]:
        stmt = select(expr, func.count()).select_from(VmImageCve).where(*conds).group_by(expr)
        return {k: int(n) for k, n in db.execute(stmt).all()}

    severity = {str(k): n for k, n in sorted(counts(VmImageCve.trivy_severity).items(), key=lambda kv: -kv[1])}
    fixed = counts(case((_is_fixed(), "yes"), else_="no"))
    return {
        "severity": severity,
        "level": _fold_levels(counts(VmImageCve.risk), f.levels),
        "fixed": {"yes": fixed.get("yes", 0), "no": fixed.get("no", 0)},
    }


def find_vuln(db: Session, image_id: int, cve_id: str, package: str, installed_version: str) -> Any:
    """Одна находка с полями витрины; None — такой находки в образе нет."""
    stmt = (
        vulns_select(VULN_COLUMNS)
        .where(
            VmImageCve.image_id == image_id, VmImageCve.cve_id == cve_id,
            VmImageCve.package == package, VmImageCve.installed_version == installed_version,
        )
    )
    return db.execute(stmt).first()


# ---- Экспорт --------------------------------------------------------------------


EXPORT_COLUMNS_SQL = [
    VmImage.project, VmImage.repository, VmImage.platform, VmImage.tags, VmImage.scan_status, VmImage.scanned_at,
    VmImageCve.cve_id, VmImageCve.package, VmImageCve.installed_version, VmImageCve.fixed_version,
    VmImageCve.trivy_severity, VmImageCve.trivy_cvss, VmImageCve.risk, VmCve.epss, VmCve.kev,
]


def iter_export_rows(db: Session, f: ImageFilters, sort: str, chunk: int = 5000) -> Iterator[dict[str, Any]]:
    """Строки выгрузки: образ × находка по фильтрам списка образов. Образ без находок — одна
    строка с пустыми колонками находки: чистый образ в выгрузке виден. Серверный курсор, а не
    страницы по offset."""
    stmt = (
        select(*EXPORT_COLUMNS_SQL)
        .select_from(VmImage)
        .outerjoin(VmImageCve, VmImageCve.image_id == VmImage.id)
        .outerjoin(VmCve, VmCve.cve_id == VmImageCve.cve_id)
        .where(*image_conditions(f))
        .order_by(*IMAGE_SORTS[sort], VmImageCve.risk.desc().nulls_last(), *_PAIR_KEY)
        .execution_options(yield_per=chunk)
    )
    for r in db.execute(stmt):
        yield {
            "image": f"{r.project}/{r.repository}",
            "platform": r.platform,
            "tags": ", ".join(parse_tags(r.tags)),
            "cve_id": r.cve_id,
            "package": r.package,
            "installed_version": r.installed_version,
            "fixed_version": r.fixed_version,
            "trivy_severity": r.trivy_severity,
            "trivy_cvss": r.trivy_cvss,
            "risk": r.risk,
            "level": level_of(r.risk, f.levels) or "",
            "epss": r.epss,
            # Признак читают глазами: «да» у KEV и пустая ячейка у остальных.
            "kev": "да" if r.kev else "",
            "scan_status": r.scan_status,
            "scanned_at": r.scanned_at,
        }

