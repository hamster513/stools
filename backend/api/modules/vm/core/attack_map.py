"""CVE → техника ATT&CK: правило по вектору CVSS и справочник CTID.

Правило грубое, но честное: у CVE нет техники, есть только способ доступа.
Справочник CTID (Mappings Explorer, раздел KEV; архив attack_to_cve)
точнее, но покрывает сотни CVE, а не сотни тысяч — поэтому он замещает
правило только там, где есть.
"""
from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterator
from typing import IO

#: cve_id, technique_id, mapping_type
Mapping = tuple[str, str, str]

MAPPING_TYPES = ("exploitation_technique", "primary_impact", "secondary_impact")


def technique_for(
    v3_av: str | None,
    v3_pr: str | None,
    v3_ui: str | None,
    v2_av: str | None,
    v2_au: str | None,
    internet: bool,
) -> str | None:
    """Техника по вектору доступа; None — если вектора нет вовсе.

    v2 берётся только когда v3 не заполнен: у старых CVE другого и нет.
    «Требуется взаимодействие» перевешивает всё остальное — это уже не
    эксплуатация сервиса, а запуск чего-то на стороне пользователя.
    """
    if v3_av:
        av, pr, ui = v3_av, v3_pr or "NONE", v3_ui or "NONE"
    elif v2_av:
        av, pr, ui = v2_av, ("NONE" if (v2_au or "NONE") == "NONE" else "LOW"), "NONE"
    else:
        return None
    if av == "NETWORK":
        if ui == "REQUIRED":
            return "T1203"
        # Публичный сервис — только если хост действительно смотрит наружу;
        # иначе это боковое перемещение внутри периметра.
        if pr == "NONE" and internet:
            return "T1190"
        return "T1210"
    if av == "ADJACENT_NETWORK":
        return "T1557"
    return "T1068"


def parse_ctid_json(fh: IO[bytes]) -> Iterator[Mapping]:
    """Mappings Explorer: `{"mapping_objects": [{capability_id, attack_object_id, mapping_type}]}`."""
    data = json.load(fh)
    for m in data.get("mapping_objects", []):
        cve, technique, kind = m.get("capability_id"), m.get("attack_object_id"), m.get("mapping_type")
        if cve and technique and kind in MAPPING_TYPES:
            yield str(cve).upper(), str(technique), str(kind)


_CSV_COLUMNS = {
    "Primary Impact": "primary_impact",
    "Secondary Impact": "secondary_impact",
    "Exploitation Technique": "exploitation_technique",
}


def parse_ctid_csv(fh: IO[bytes]) -> Iterator[Mapping]:
    """Архивный `Att&ckToCveMappings.csv`: колонка на тип связи, техники через `;`."""
    text = io.TextIOWrapper(fh, encoding="utf-8-sig", newline="")
    for row in csv.DictReader(text):
        cve = (row.get("CVE ID") or "").strip().upper()
        if not cve:
            continue
        for column, kind in _CSV_COLUMNS.items():
            for technique in (row.get(column) or "").split(";"):
                if technique.strip():
                    yield cve, technique.strip(), kind
