"""Обход входа очистки (спека §3, §5): zip во вложенном zip, json.gz, CP1251, octets, не-текст, потолок."""
from __future__ import annotations

import base64
import gzip
import io
import json
import zipfile
from pathlib import Path

import pytest

from api.modules.toolbox.core.scrub.files import Entry, UnpackLimit, rewrite, walk
from kbaudit.safe_io import MB
from tests.toolbox.synthetic import EXPORT_JSON, TEXT

NOTES = "Хост host01 в сети 10.1.2.15\r\nвторая строка\r\n"


def zipped(members: dict[str, bytes]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return out.getvalue()


@pytest.fixture
def archive(tmp_path: Path) -> Path:
    path = tmp_path / "outer.zip"
    path.write_bytes(zipped({
        "export.json.gz": gzip.compress(json.dumps(EXPORT_JSON, indent=2).encode()),
        "host01-notes.txt": NOTES.encode("cp1251"),
        "inner.zip": zipped({"log.txt": TEXT.encode()}),
    }))
    return path


def collected(source: Path) -> list[tuple[Entry, list[tuple[str, str]]]]:
    return [(entry, list(chunks)) for entry, chunks in walk(source)]


def to_host_alias(json_key: str, text: str) -> str:
    return text.replace("host01", "host-0001")


def test_walk_zip_with_json_gz_cp1251_and_nested_zip(archive: Path) -> None:
    found = collected(archive)
    assert [(e.path, e.kind) for e, _ in found] == [
        ("outer.zip:export.json.gz", "json"),
        ("outer.zip:host01-notes.txt", "text"),
        ("outer.zip:inner.zip:log.txt", "text"),
    ]
    notes = found[1][1]
    assert ("__name__", "host01-notes.txt") in notes
    assert ("", "Хост host01 в сети 10.1.2.15\r\n") in notes
    log = found[2][1]
    # Имя вложенного архива — тоже кусок: в нём бывают имена хостов.
    assert ("__name__", "inner.zip") in log and ("__name__", "log.txt") in log
    assert "".join(text for key, text in log if key == "") == TEXT


def test_rewrite_keeps_composition_types_and_encoding(archive: Path, tmp_path: Path) -> None:
    target = tmp_path / "out" / "clean.zip"
    entries = rewrite(archive, target, to_host_alias)
    assert [e.kind for e in entries] == ["json", "text", "text"]
    with zipfile.ZipFile(target) as zf:
        assert zf.namelist() == ["export.json.gz", "host-0001-notes.txt", "inner.zip"]
        exported = zf.read("export.json.gz")
        notes = zf.read("host-0001-notes.txt")
        inner = zf.read("inner.zip")
    assert exported[:2] == b"\x1f\x8b"
    data = gzip.decompress(exported).decode()
    assert " " not in data.replace("host-0001", "")  # компактный JSON
    assert json.loads(data)["hosts"][0]["hostname"] == "host-0001.corp.test"
    assert notes.decode("cp1251") == NOTES.replace("host01", "host-0001")
    with zipfile.ZipFile(io.BytesIO(inner)) as zf:
        assert zf.read("log.txt").decode() == TEXT.replace("host01", "host-0001")


def test_json_octets_become_address_chunk_and_are_written_back(tmp_path: Path) -> None:
    source = tmp_path / "ksc.json"
    source.write_text(json.dumps(EXPORT_JSON), encoding="utf-8")
    chunks = collected(source)[0][1]
    assert ("octets", "10.1.2.15") in chunks
    assert ("version", "12.3.0.0") in chunks
    assert ("__key__", "hostname") in chunks and ("hostname", "host01.corp.test") in chunks

    def shift(json_key: str, text: str) -> str:
        return text.replace("10.1.2.15", "10.201.2.15")

    target = tmp_path / "clean.json"
    rewrite(source, target, shift)
    host = json.loads(target.read_text(encoding="utf-8"))["hosts"][0]
    assert host["ip"] == "10.201.2.15"
    assert base64.b64decode(host["octets"]["value"]) == bytes([10, 201, 2, 15])


def test_bom_is_kept(tmp_path: Path) -> None:
    source = tmp_path / "bom.txt"
    source.write_bytes(b"\xef\xbb\xbfhost01\n")
    assert collected(source)[0][1] == [("", "host01\n")]
    target = tmp_path / "clean.txt"
    rewrite(source, target, to_host_alias)
    assert target.read_bytes() == b"\xef\xbb\xbfhost-0001\n"
    # В архиве поток записи не перематывается — BOM всё равно на месте, и порядок байт тот же.
    packed = tmp_path / "bom.zip"
    packed.write_bytes(zipped({"le.txt": "host01\n".encode("utf-16"), "be.txt": b"\xfe\xff" + "host01\n".encode("utf-16-be")}))
    rewrite(packed, tmp_path / "clean.zip", to_host_alias)
    with zipfile.ZipFile(tmp_path / "clean.zip") as zf:
        assert zf.read("le.txt") == b"\xff\xfe" + "host-0001\n".encode("utf-16-le")
        assert zf.read("be.txt") == b"\xfe\xff" + "host-0001\n".encode("utf-16-be")


def test_binary_is_skipped_and_not_written(tmp_path: Path) -> None:
    source = tmp_path / "mixed.zip"
    source.write_bytes(zipped({"tool.bin": b"MZ\x00\x01\x02binary", "a.txt": b"host01\n"}))
    assert [(e.path, e.kind) for e, _ in collected(source)] == [
        ("mixed.zip:tool.bin", "skipped"), ("mixed.zip:a.txt", "text"),
    ]
    target = tmp_path / "clean.zip"
    entries = rewrite(source, target, to_host_alias)
    assert [e.kind for e in entries] == ["skipped", "text"]
    with zipfile.ZipFile(target) as zf:
        assert zf.namelist() == ["a.txt"]

    lone = tmp_path / "tool.bin"
    lone.write_bytes(b"\x00\x01\x02")
    assert rewrite(lone, tmp_path / "tool-clean.bin", to_host_alias) == [Entry("tool.bin", "skipped")]
    assert not (tmp_path / "tool-clean.bin").exists()


def test_unpack_limit_is_an_error_not_memory_exhaustion(tmp_path: Path) -> None:
    bomb = tmp_path / "bomb.txt.gz"
    block = b"0" * MB
    # Пустышка собирается потоком: 600 МБ в памяти теста не бывает.
    with gzip.GzipFile(bomb, "wb", compresslevel=1) as gz:
        for _ in range(600):
            gz.write(block)
    with pytest.raises(UnpackLimit):
        for _, chunks in walk(bomb):
            for _ in chunks:
                pass
