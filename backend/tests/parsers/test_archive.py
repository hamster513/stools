import zipfile
from collections.abc import Callable
from pathlib import Path

from kbaudit.models import ObjectType
from kbaudit.parsers.archive import group_by_uuid, object_type_of, read_text

U1 = "000ffb49-bb9e-4ee4-9262-6754b7ee28d2"
U2 = "111ffb49-bb9e-4ee4-9262-6754b7ee28d2"


def test_groups_members_by_trailing_uuid(synthetic_zip: Callable[..., Path]) -> None:
    path = synthetic_zip({
        f"correlation-rules/rules/correlation/{U1}/R1.co": "x",
        f"correlation-rules/rules/correlation/{U1}/metainfo.yaml": "y",
        f"correlation-rules/rules/correlation/{U2}/R2.co": "z",
        "filters/aaa/whatever.flt": "q",
    })
    with zipfile.ZipFile(path) as zf:
        groups = group_by_uuid(zf, "correlation-rules/")
    assert set(groups) == {U1, U2}
    assert len(groups[U1]) == 2


def test_directory_entries_are_ignored(synthetic_zip: Callable[..., Path]) -> None:
    path = synthetic_zip({
        f"correlation-rules/rules/correlation/{U1}/": "",
        f"correlation-rules/rules/correlation/{U1}/R1.co": "x",
    })
    with zipfile.ZipFile(path) as zf:
        assert len(group_by_uuid(zf, "correlation-rules/")[U1]) == 1


def test_object_type_by_top_directory() -> None:
    assert object_type_of("correlation-rules/rules/correlation/x/R.co") == ObjectType.CORRELATION
    assert object_type_of("filters/x/F.flt") == ObjectType.FILTER
    assert object_type_of("enrichment-rules/x/E.en") == ObjectType.ENRICHMENT
    assert object_type_of("aggregation-rules/x/A.agr") == ObjectType.AGGREGATION
    assert object_type_of("taxonomy.json") is None


def test_read_text_strips_bom(synthetic_zip: Callable[..., Path]) -> None:
    path = synthetic_zip({"a.txt": "﻿текст"})
    with zipfile.ZipFile(path) as zf:
        assert read_text(zf, "a.txt") == "текст"
