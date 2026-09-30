"""Файл выгрузки сборщика: собранное пишется в gzip потоком тем же текстом, что json.dumps."""
from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from api import export_files
from api.export_files import store_gz, write_json_gz


def _sample() -> dict[str, Any]:
    return {
        "format": "stools-ad/1",
        "collected_at": "2026-09-30T10:00:00+00:00",
        "objects": [{"dn": "CN=Пётр,DC=corp", "uac": 512, "member": []}, {"dn": "CN=x", "spn": ["a/b"], "n": None, "f": 1.5}],
        "empty_list": [],
        "empty_dict": {},
        "principals": {"S-1-5-21-1": {"name": "CORP\\ёж", "class": "user"}, "S-1-5-21-2": {"name": "\"q\"", "class": ""}},
        "flag": True,
    }


@pytest.mark.parametrize("chunk", [1, 64, 1024 * 1024])
def test_streamed_text_and_sha_match_json_dumps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, chunk: int) -> None:
    monkeypatch.setattr(export_files, "CHUNK", chunk)
    obj = _sample()
    path = tmp_path / "e.json.gz"
    sha = write_json_gz(obj, path)
    text = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    assert gzip.decompress(path.read_bytes()) == text
    assert sha == hashlib.sha256(text).hexdigest()


def test_store_moves_gzip_and_compresses_plain(tmp_path: Path) -> None:
    text = json.dumps(_sample(), ensure_ascii=False).encode("utf-8")
    packed = tmp_path / "up.gz"
    packed.write_bytes(gzip.compress(text))
    body = packed.read_bytes()
    store_gz(packed, tmp_path / "1.json.gz")
    assert not packed.exists() and (tmp_path / "1.json.gz").read_bytes() == body
    plain = tmp_path / "up.json"
    plain.write_bytes(text)
    store_gz(plain, tmp_path / "2.json.gz")
    assert gzip.decompress((tmp_path / "2.json.gz").read_bytes()) == text
