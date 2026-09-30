"""Файлы выгрузок сборщиков (AD, KSC): собранное — в gzip потоком, загрузка — в хранилище переносом.

Выгрузка крупного домена — сотни мегабайт JSON. Раньше собранный словарь
превращался в строку, строка — в байты, байты разбирались и в конце ещё раз
сжимались: все копии жили в памяти рабочего процесса одновременно с
находками. Теперь текст идёт в файл кусками, разбор читает файл, а готовый
gzip становится файлом снапшота переименованием.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

GZIP_MAGIC = b"\x1f\x8b"
#: Сколько текста копится перед записью в gzip: и память, и число вызовов сжатия.
CHUNK = 1024 * 1024


def _pieces(obj: dict[str, Any]) -> Iterator[str]:
    """Текст `json.dumps(obj, ensure_ascii=False)` по частям: списки и словари
    верхнего уровня — по элементу. Ключи — строки, как в любой выгрузке JSON."""
    def dumps(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False)

    yield "{"
    for i, (key, value) in enumerate(obj.items()):
        yield (", " if i else "") + dumps(key) + ": "
        if isinstance(value, list):
            yield "["
            for j, item in enumerate(value):
                yield (", " if j else "") + dumps(item)
            yield "]"
        elif isinstance(value, dict):
            yield "{"
            for j, (k, v) in enumerate(value.items()):
                yield (", " if j else "") + dumps(k) + ": " + dumps(v)
            yield "}"
        else:
            yield dumps(value)
    yield "}"


def write_json_gz(obj: dict[str, Any], path: Path) -> str:
    """Записать `obj` в gzip-файл `path` без полной строки JSON в памяти.
    Возвращает sha256 несжатого текста — тот же, что от `json.dumps(obj, ensure_ascii=False).encode()`."""
    digest = hashlib.sha256()
    # Без имени файла в заголовке gzip — как у gzip.compress.
    with path.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw) as gz:
        buf: list[str] = []
        size = 0
        for piece in _pieces(obj):
            buf.append(piece)
            size += len(piece)
            if size >= CHUNK:
                data = "".join(buf).encode("utf-8")
                digest.update(data)
                gz.write(data)
                buf.clear()
                size = 0
        data = "".join(buf).encode("utf-8")
        digest.update(data)
        gz.write(data)
    return digest.hexdigest()


def is_gzip(path: Path) -> bool:
    with path.open("rb") as f:
        return f.read(2) == GZIP_MAGIC


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def store_gz(src: Path, dst: Path) -> None:
    """Файл выгрузки — в хранилище: gzip переносится как есть (тот же каталог
    данных, переименование), несжатый JSON сжимается потоком, а `src` остаётся."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    if is_gzip(src):
        src.replace(dst)
        return
    with src.open("rb") as f, dst.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw) as gz:
        shutil.copyfileobj(f, gz, CHUNK)
