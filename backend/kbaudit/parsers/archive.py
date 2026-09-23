"""Обход zip-выгрузки. Полный, не «первые N» — порядок файлов в архиве не алфавитный."""
from __future__ import annotations

import zipfile
from collections import defaultdict
from pathlib import PurePosixPath

from kbaudit import safe_io
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


def check_sizes(zf: zipfile.ZipFile) -> None:
    """Размеры членов по заголовкам: каждый не больше 512 МБ, все вместе — 2 ГБ.

    Вызывается сразу после открытия архива: дальше его читают разные
    разборщики, и суммарный лимит иначе не соблюсти.
    """
    safe_io.check_zip_sizes(zf, safe_io.ZIP_MEMBER_LIMIT, safe_io.ZIP_TOTAL_LIMIT)


def read_text(zf: zipfile.ZipFile, member: str) -> str:
    data = safe_io.read_zip_member(zf, member, safe_io.ZIP_MEMBER_LIMIT)
    return data.decode("utf-8-sig", errors="replace")
