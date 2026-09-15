import json
import zipfile
from collections.abc import Callable
from pathlib import Path

from kbaudit.parsers.taxonomy import load_taxonomy


def test_reads_fields_and_version(synthetic_zip: Callable[..., Path]) -> None:
    doc = {
        "_build_info": {"version": "26.2.1"},
        "src": {"ip": "string"},
        "subject": {"account": {"name": "string"}},
    }
    path = synthetic_zip({"taxonomy.json": json.dumps(doc)})
    with zipfile.ZipFile(path) as zf:
        tax = load_taxonomy(zf)
    assert tax.fields == {"src", "subject"}
    assert tax.version == "26.2.1"


def test_missing_taxonomy_gives_empty(synthetic_zip: Callable[..., Path]) -> None:
    path = synthetic_zip({"readme.txt": "нет таксономии"})
    with zipfile.ZipFile(path) as zf:
        tax = load_taxonomy(zf)
    assert tax.fields == set()
    assert tax.version is None


def test_bom_is_tolerated(synthetic_zip: Callable[..., Path]) -> None:
    path = synthetic_zip({"taxonomy.json": "﻿" + json.dumps({"dst": {}})})
    with zipfile.ZipFile(path) as zf:
        assert load_taxonomy(zf).fields == {"dst"}
