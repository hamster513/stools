"""Обход zip-выгрузки. Полный, не «первые N» — порядок файлов в архиве не алфавитный."""
from __future__ import annotations

import zipfile
from collections import defaultdict
from pathlib import PurePosixPath

from kbaudit.models import ObjectType

#: Расширения тел по типам объектов.
BODY_EXT_BY_TYPE: dict[ObjectType, set[str]] = {
    ObjectType.CORRELATION: {".co", ".cojs"},
    ObjectType.FILTER: {".flt"},
    ObjectType.ENRICHMENT: {".en"},
    ObjectType.AGGREGATION: {".agr"},
}

_TOP_DIR_TO_TYPE: dict[str, ObjectType] = {
    "correlation-rules": ObjectType.CORRELATION,
    "filters": ObjectType.FILTER,
    "enrichment-rules": ObjectType.ENRICHMENT,
    "aggregation-rules": ObjectType.AGGREGATION,
}


def _is_uuid(part: str) -> bool:
    return len(part) == 36 and part.count("-") == 4


def group_by_uuid(zf: zipfile.ZipFile, prefix: str) -> dict[str, list[str]]:
    """Файлы архива под prefix, сгруппированные по последнему UUID в пути."""
    groups: dict[str, list[str]] = defaultdict(list)
    for name in zf.namelist():
        if name.endswith("/") or not name.startswith(prefix):
            continue
        uuids = [p for p in PurePosixPath(name).parts if _is_uuid(p)]
        if uuids:
            groups[uuids[-1]].append(name)
    return {k: sorted(v) for k, v in groups.items()}


def object_type_of(member: str) -> ObjectType | None:
    parts = PurePosixPath(member).parts
    if len(parts) < 2:
        return None
    return _TOP_DIR_TO_TYPE.get(parts[0])


def read_text(zf: zipfile.ZipFile, member: str) -> str:
    return zf.read(member).decode("utf-8-sig", errors="replace")
