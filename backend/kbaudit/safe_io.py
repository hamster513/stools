"""Распаковка с потолком: gzip и члены zip читаются кусками со счётчиком байт.

Размер загрузки ничего не говорит о размере распакованного: сжатие даёт до
~1000:1, и gzip в мегабайт разворачивается в гигабайт в памяти единственного
воркера (аудит H2). Всё, что распаковывает присланный человеком файл, идёт
через эти функции, и превышение — `ValueError` с лимитом в тексте.

Результат копится в одном `bytearray`, а не списком кусков с `join` в конце:
иначе на пике в памяти два результата сразу (финальное ревью, I2). Отдаётся
тот же `bytearray` без копии в `bytes` — `json.loads`, `ElementTree` и
`.decode` принимают его как есть.

Модуль в ядре, а не в `api/`: zip разбирают разборщики ядра (архив базы
знаний, xlsx), а ядро не зависит от слоя HTTP.
"""
from __future__ import annotations

import gzip
import io
import zipfile
from typing import BinaryIO

MB = 1024 * 1024
#: Потолок одного члена zip-архива и всех членов вместе. Действуют
#: на архив базы знаний и на xlsx; тесты подменяют их на мегабайт.
ZIP_MEMBER_LIMIT = 512 * MB
ZIP_TOTAL_LIMIT = 2048 * MB

_CHUNK = MB


def _too_big(what: str, max_bytes: int) -> ValueError:
    return ValueError(f"{what}распакованный размер больше лимита ({max_bytes // MB} МБ)")


def decompress_gzip(data: bytes | bytearray, max_bytes: int) -> bytearray:
    """Распаковать gzip, но не больше `max_bytes`. Битый gzip — `OSError`/`EOFError`, битый поток deflate — `zlib.error` (не `OSError`), как у `gzip.decompress`."""
    return decompress_gzip_file(io.BytesIO(data), max_bytes)


def decompress_gzip_file(fileobj: BinaryIO, max_bytes: int) -> bytearray:
    """То же для открытого файла: сжатые байты не читаются в память целиком."""
    out = bytearray()
    with gzip.GzipFile(fileobj=fileobj) as gz:
        while chunk := gz.read(_CHUNK):
            if len(out) + len(chunk) > max_bytes:
                raise _too_big("", max_bytes)
            out += chunk
    return out


def read_zip_member(zf: zipfile.ZipFile, member: str | zipfile.ZipInfo, max_bytes: int) -> bytearray:
    """Прочитать член архива, но не больше `max_bytes`.

    Сначала размер из заголовка — отказ без распаковки. Счётчик при чтении
    — вторая линия: `zipfile` сам не отдаёт больше `file_size`, но полагаться
    на внутренности библиотеки там, где граница безопасности, не хочется.
    """
    info = member if isinstance(member, zipfile.ZipInfo) else zf.getinfo(member)
    if info.file_size > max_bytes:
        raise _too_big(f"{info.filename}: ", max_bytes)
    out = bytearray()
    with zf.open(info) as fh:
        while chunk := fh.read(_CHUNK):
            if len(out) + len(chunk) > max_bytes:
                raise _too_big(f"{info.filename}: ", max_bytes)
            out += chunk
    return out


def check_zip_sizes(zf: zipfile.ZipFile, max_member: int, max_total: int) -> None:
    """Проверить размеры всех членов по заголовкам до разбора.

    Разборщик читает архив во многих местах; проверка на входе ограничивает
    каждое из них сразу, и суммарный лимит иначе не соблюсти.
    """
    total = 0
    for info in zf.infolist():
        if info.file_size > max_member:
            raise _too_big(f"{info.filename}: ", max_member)
        total += info.file_size
    if total > max_total:
        raise _too_big("архив: ", max_total)
