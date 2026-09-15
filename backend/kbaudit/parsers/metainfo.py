"""Разбор metainfo.yaml. Пять форм: корреляция, нормализация, агрегация,
обогащение, фильтр — различаются набором ключей, не отдельными парсерами."""
from __future__ import annotations

import re
from typing import Any

import yaml

from kbaudit.models import MetaInfo

RE_CORR_NAME = re.compile(r'correlation_name\s*=\s*"([^"]+)"')

#: Строковый "null" в Criteria — артефакт выгрузки, а не имя правила.
NOT_A_NAME = {"null", "none", ""}


def parse_metainfo(raw: bytes) -> MetaInfo:
    try:
        doc: Any = yaml.safe_load(raw.decode("utf-8-sig", errors="replace"))
    except yaml.YAMLError:
        return MetaInfo()
    if not isinstance(doc, dict):
        return MetaInfo()

    criteria: list[str] = []
    for entry in doc.get("EventDescriptions") or []:
        if isinstance(entry, dict) and isinstance(entry.get("Criteria"), str):
            criteria.append(entry["Criteria"])

    names: set[str] = set()
    for text in criteria:
        names.update(
            n for n in RE_CORR_NAME.findall(text) if n.strip().lower() not in NOT_A_NAME
        )

    return MetaInfo(
        object_id=doc.get("ObjectId"),
        origin=doc.get("Origin"),
        category=doc.get("Category"),
        rule_name=doc.get("Rule"),
        criteria=criteria,
        correlation_names=sorted(names),
    )
