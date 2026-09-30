"""Данные ЦС домена: хранение загрузок, свежесть по разделам, список, удаление.

Разделы собираются по отдельности (пункты 5–7 меню сборщика), поэтому анализ
берёт каждый раздел из самой свежей загрузки, где он есть: `dc` может прийти
раньше `ca`, и новая загрузка одного `ca` не должна стирать известное про `dc`.
"""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.ad.core.ca_data import MERGED_FIELDS, SECTION_FIELD, SECTIONS, CaData
from api.modules.ad.models import AdCaData, AdDomain


def store_ca_data(db: Session, data: CaData, *, filename: str, sha256: str, uploaded_by: str) -> AdCaData:
    """Домен ищется по data.domain.sid; нет — ValueError('домен … не найден: сначала загрузите выгрузку домена')."""
    domain = db.execute(select(AdDomain).where(AdDomain.sid == data.domain.sid)).scalars().first()
    if domain is None:
        raise ValueError(f"домен {data.domain.dns_root or data.domain.sid} не найден: сначала загрузите выгрузку домена")
    row = AdCaData(
        domain_id=domain.id,
        collected_at=data.collected_at,
        filename=filename[:255],
        sha256=sha256,
        uploaded_by=uploaded_by,
        sections_json=json.dumps(list(data.sections)),
        data=data.model_dump(mode="json", exclude=MERGED_FIELDS),
    )
    db.add(row)
    db.flush()
    return row


def _rows(db: Session, domain_id: int) -> list[AdCaData]:
    return list(
        db.execute(
            select(AdCaData).where(AdCaData.domain_id == domain_id).order_by(AdCaData.collected_at.desc(), AdCaData.id.desc())
        ).scalars()
    )


def effective_ca_data(db: Session, domain_id: int) -> tuple[CaData | None, int | None]:
    """Самые свежие данные по каждому разделу отдельно (по collected_at), сведённые в один CaData;
    у каждого раздела — дата сбора и id загрузки, откуда он взят (`section_dates`, `section_sources`);
    второй элемент — id самой свежей загрузки. Нет загрузок — (None, None)."""
    rows = _rows(db, domain_id)
    if not rows:
        return None, None
    merged = CaData.model_validate(rows[0].data)
    merged.sections, merged.cas, merged.dcs, merged.web = [], [], [], []
    for section in SECTIONS:
        row = next((r for r in rows if section in json.loads(r.sections_json)), None)
        if row is None:
            continue
        field = SECTION_FIELD[section]
        source = CaData.model_validate(row.data)
        setattr(merged, field, getattr(source, field))
        merged.sections.append(section)
        merged.section_dates[section] = source.collected_at
        merged.section_sources[section] = row.id
    return merged, rows[0].id


def list_ca_data(db: Session, domain_id: int) -> list[dict[str, Any]]:
    return [
        {
            "id": r.id,
            "collected_at": r.collected_at,
            "imported_at": r.imported_at,
            "filename": r.filename,
            "uploaded_by": r.uploaded_by,
            "sections": json.loads(r.sections_json),
            "cas": len(r.data.get("cas") or []),
            "dcs": len(r.data.get("dcs") or []),
            "web": len(r.data.get("web") or []),
        }
        for r in _rows(db, domain_id)
    ]


def delete_ca_data(db: Session, row: AdCaData) -> None:
    db.delete(row)
    db.commit()
