import json
import zipfile
from collections.abc import Callable
from pathlib import Path

from kbaudit.parsers.tables import load_table_lists, load_table_values


def test_collects_nested_string_values(synthetic_zip: Callable[..., Path]) -> None:
    doc = {
        "DEMO_Internal_Networks": {"rows": [["10.0.0.0/8"], ["192.168.0.0/16"]]},
        "DEMO_Default_Usernames": {"rows": [["Administrator"]]},
    }
    path = synthetic_zip({"correlation_defaults.json": json.dumps(doc)})
    with zipfile.ZipFile(path) as zf:
        values = load_table_values(zf)
    assert "10.0.0.0/8" in values
    assert "administrator" in values, "значения нормализуются в нижний регистр"


def test_too_short_and_too_long_values_are_skipped(
    synthetic_zip: Callable[..., Path],
) -> None:
    doc = {"T": {"rows": [["a"], ["x" * 200], ["ok_value"]]}}
    path = synthetic_zip({"correlation_defaults.json": json.dumps(doc)})
    with zipfile.ZipFile(path) as zf:
        values = load_table_values(zf)
    assert values == {"ok_value"}


def test_table_lists_report_emptiness(synthetic_zip: Callable[..., Path]) -> None:
    doc = {"Filled": {"rows": [["abc"], ["def"]]}, "Empty": {"rows": []}}
    path = synthetic_zip({"correlation_defaults.json": json.dumps(doc)})
    with zipfile.ZipFile(path) as zf:
        lists = {t.name: t for t in load_table_lists(zf)}
    assert lists["Filled"].value_count == 2
    assert lists["Empty"].is_empty is True


def test_missing_file_is_not_an_error(synthetic_zip: Callable[..., Path]) -> None:
    path = synthetic_zip({"readme.txt": "пусто"})
    with zipfile.ZipFile(path) as zf:
        assert load_table_values(zf) == set()
        assert load_table_lists(zf) == []
