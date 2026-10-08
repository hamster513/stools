"""Обход входа очистки: zip (и вложенные), gz, json, текст построчно; сборка результата того же типа.

Определение типа, кодировки и обход JSON с `octets` перенесены из `backend/tools/export_scrub.py`
(скрипт заморожен). В отличие от скрипта, файл не читается в память целиком: zip — по записям,
gz — потоком, текст — построчно; потолок распакованного объёма считается по ходу чтения.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import io
import json
import shutil
import tempfile
import zipfile
import zlib
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, ExitStack, contextmanager
from dataclasses import dataclass
from functools import partial
from ipaddress import IPv4Address
from itertools import chain
from pathlib import Path
from typing import IO, Any, NamedTuple

from kbaudit.safe_io import MB

#: Потолок распакованного, как у AD: gzip разворачивается до ~1000:1.
MAX_UNPACKED = 512 * MB
BLOCK = MB
#: Вложенный архив меньше этого держится в памяти, больше — во временном файле.
SPOOL = 64 * MB
#: BOM снимается при чтении и ставится обратно при записи: кодировки ниже — без BOM. Средствами
#: TextIOWrapper нельзя: в поток записи члена zip (не перематывается) он BOM не пишет.
BOMS = {b"\xef\xbb\xbf": "utf-8", b"\xff\xfe": "utf-16-le", b"\xfe\xff": "utf-16-be"}
#: Так рвётся повреждённый архив или чтение: такой файл — запись `broken`, в результат не идёт.
BROKEN = (OSError, EOFError, zipfile.BadZipFile, zlib.error)
#: Ключи кусков, которые не значения JSON: имя файла в архиве и имя ключа JSON.
NAME = "__name__"
KEY = "__key__"
OCTETS = "octets"

Opener = Callable[[], AbstractContextManager[IO[bytes]]]
Chunks = Iterator[tuple[str, str]]
Transform = Callable[[str, str], str]


class UnpackLimit(Exception):
    """Распаковано больше MAX_UNPACKED."""


@dataclass(slots=True)
class Entry:
    path: str  # «архив.zip:внутри/файл.json»
    # json | text | skipped (не текст) | broken (ошибка чтения или повреждённый архив)
    kind: str


class _Budget:
    def __init__(self) -> None:
        self.used = 0

    def add(self, size: int) -> None:
        self.used += size
        if self.used > MAX_UNPACKED:
            raise UnpackLimit(f"распакованный размер больше лимита ({MAX_UNPACKED // MB} МБ)")


_TEXT = object()  # вместо разобранного JSON: файл читается построчно


class _Codec(NamedTuple):
    bom: bytes
    encoding: str


def walk(source: Path) -> Iterator[tuple[Entry, Chunks]]:
    """Для каждого файла (включая лежащие в zip, во вложенных zip, в .gz) — запись и итератор кусков
    (json_key, text). Итератор кусков читается до следующего шага `walk`: он читает из открытого архива.

    Имена файлов в архиве — куски с ключом `__name__`, имена ключей JSON — с `__key__`, двоичный адрес
    `octets` — кусок с адресом текстом. Распаковано больше MAX_UNPACKED — `UnpackLimit`.
    """
    yield from _walk(source.name, source.name, lambda: source.open("rb"), _Budget(), [])


def rewrite(source: Path, target: Path, transform: Transform) -> list[Entry]:
    """Тот же обход, но каждый кусок проходит через `transform(json_key, text)` и пишется в результат
    того же типа: zip → zip, .gz → .gz, json → компактный json, текст — той же кодировкой и с теми же
    концами строк. Не-текст в результат не попадает; если весь вход — не текст, `target` не создаётся.
    При `UnpackLimit` недописанный `target` удаляет вызывающий."""
    entries: list[Entry] = []
    target.parent.mkdir(parents=True, exist_ok=True)
    _rewrite(source.name, source.name, lambda: source.open("rb"), _Budget(), transform, entries,
             lambda: target.open("wb"), top=True)
    return entries


# --- распознавание -----------------------------------------------------------------------------

def _classify(name: str, opener: Opener) -> str:
    try:
        with opener() as f:
            head = f.read(4)
    except BROKEN:
        return "broken"
    low = name.lower()
    if low.endswith(".zip") or head == b"PK\x03\x04":
        return "zip"
    if low.endswith(".gz") or head[:2] == b"\x1f\x8b":
        return "gz"
    return "file"


def _inner(name: str) -> str:
    return name[:-3] if name.lower().endswith(".gz") else name


def _gunzip(opener: Opener) -> Opener:
    @contextmanager
    def open_() -> Iterator[IO[bytes]]:
        with opener() as raw, gzip.GzipFile(fileobj=raw, mode="rb") as stream:
            yield stream  # type: ignore[misc]
    return open_


def _copy(source: IO[bytes], target: IO[bytes], budget: _Budget) -> None:
    while block := source.read(BLOCK):
        budget.add(len(block))
        target.write(block)


@contextmanager
def _zip_in(opener: Opener, budget: _Budget) -> Iterator[zipfile.ZipFile]:
    with opener() as raw, ExitStack() as stack:
        stream = raw
        # zipfile читает каталог с конца: член архива и gz «перематываются» только перечитыванием.
        if not isinstance(raw, io.BufferedReader):
            spool = stack.enter_context(tempfile.SpooledTemporaryFile(SPOOL))
            _copy(raw, spool, budget)
            spool.seek(0)
            stream = spool
        with zipfile.ZipFile(stream) as zf:
            yield zf


def _probe(opener: Opener, budget: _Budget) -> tuple[_Codec, str] | str:
    """Кодировка и первый непробельный символ; иначе вид записи: skipped или broken. Читает файл
    целиком, считая байты: кодировка без BOM известна только в конце (utf-8, иначе cp1251)."""
    try:
        with opener() as f:
            block = f.read(BLOCK)
            bom = next((b for b in BOMS if block.startswith(b)), b"")
            encodings = [BOMS[bom]] if bom else ["utf-8", "cp1251"]
            block = block[len(bom):]
            decoders = {enc: codecs.getincrementaldecoder(enc)() for enc in encodings}
            first = dict.fromkeys(encodings, "")
            while True:
                budget.add(len(block))
                for enc, decoder in list(decoders.items()):
                    try:
                        text = decoder.decode(block, final=not block)
                    except UnicodeDecodeError:
                        del decoders[enc]
                        continue
                    if "\x00" in text:
                        del decoders[enc]
                    elif not first[enc]:
                        first[enc] = text.lstrip()[:1]
                if not decoders:
                    return "skipped"
                if not block:
                    break
                block = f.read(BLOCK)
    except BROKEN:
        return "broken"
    encoding = next(iter(decoders))
    return _Codec(bom, encoding), first[encoding]


def _leaf(opener: Opener, budget: _Budget) -> tuple[_Codec, Any] | str:
    """(кодировка, разобранный JSON или _TEXT); иначе вид записи: skipped или broken."""
    probed = _probe(opener, budget)
    if isinstance(probed, str):
        return probed
    codec, first = probed
    if first in ("{", "["):
        # Целиком, как load_export в AD: память защищает потолок, проверенный в _probe.
        with opener() as f:
            raw = f.read()
        try:
            return codec, json.loads(raw[len(codec.bom):].decode(codec.encoding))
        except ValueError:
            pass
    return codec, _TEXT


def _octets(key: str, value: dict[str, Any]) -> str | None:
    """Двоичный адрес KSC (`octets`, 4 байта base64) текстом."""
    inner = value.get("value")
    if key.lower() != OCTETS or value.get("type") != "binary" or not isinstance(inner, str):
        return None
    try:
        raw = base64.b64decode(inner, validate=True)
    except (binascii.Error, ValueError):
        return None
    return ".".join(str(b) for b in raw) if len(raw) == 4 else None


# --- обход -------------------------------------------------------------------------------------

def _walk(label: str, name: str, opener: Opener, budget: _Budget,
          names: list[tuple[str, str]]) -> Iterator[tuple[Entry, Chunks]]:
    kind = _classify(name, opener)
    if kind == "zip":
        yield from _walk_zip(label, opener, budget, names)
        return
    if kind == "gz":
        yield from _walk(label, _inner(name), _gunzip(opener), budget, names)
        return
    leaf = _leaf(opener, budget) if kind == "file" else kind
    if isinstance(leaf, str):
        yield Entry(label, leaf), iter(())
        return
    # Имена архивов и файлов на пути к этому файлу — первыми его кусками: в результат они попадут с ним.
    pending = names[:]
    names.clear()
    codec, data = leaf
    if data is _TEXT:
        yield Entry(label, "text"), chain(pending, _lines(opener, codec))
    else:
        yield Entry(label, "json"), chain(pending, _json_chunks(data, ""))


def _walk_zip(label: str, opener: Opener, budget: _Budget,
              names: list[tuple[str, str]]) -> Iterator[tuple[Entry, Chunks]]:
    with ExitStack() as stack:
        try:
            zin = stack.enter_context(_zip_in(opener, budget))
        except BROKEN:
            yield Entry(label, "broken"), iter(())
            return
        for info in zin.infolist():
            if info.is_dir():
                continue
            mark = len(names)
            names.append((NAME, info.filename))
            yield from _walk(f"{label}:{info.filename}", info.filename, partial(zin.open, info), budget, names)
            # Имя не забрал ни один файл — в результат эта запись не попадёт (не текст или пустой архив).
            del names[mark:]


def _lines(opener: Opener, codec: _Codec) -> Chunks:
    with opener() as raw:
        raw.read(len(codec.bom))
        reader = io.TextIOWrapper(raw, encoding=codec.encoding, newline="")
        try:
            for line in reader:
                yield "", line
        finally:
            reader.detach()


def _json_chunks(value: Any, key: str) -> Chunks:
    if isinstance(value, dict):
        address = _octets(key, value)
        if address is not None:
            yield OCTETS, address
            return
        for k, v in value.items():
            yield KEY, k
            yield from _json_chunks(v, k)
    elif isinstance(value, list):
        for v in value:
            yield from _json_chunks(v, key)
    elif isinstance(value, str):
        yield key, value


# --- сборка результата -------------------------------------------------------------------------

def _rewrite(label: str, name: str, opener: Opener, budget: _Budget, transform: Transform,
             entries: list[Entry], sink: Opener, *, top: bool = False) -> bool:
    """Пишет результат в `sink`, только если есть что писать; True — записан."""
    kind = _classify(name, opener)
    if kind == "zip":
        return _rewrite_zip(label, opener, budget, transform, entries, sink, top=top)
    if kind == "gz":
        return _rewrite(label, _inner(name), _gunzip(opener), budget, transform, entries, _gzip(sink), top=top)
    leaf = _leaf(opener, budget) if kind == "file" else kind
    if isinstance(leaf, str):
        entries.append(Entry(label, leaf))
        return False
    codec, data = leaf
    with sink() as out:
        out.write(codec.bom)
        if data is _TEXT:
            entries.append(Entry(label, "text"))
            with opener() as raw:
                raw.read(len(codec.bom))
                _rewrite_lines(raw, out, codec.encoding, transform)
        else:
            entries.append(Entry(label, "json"))
            clean = _json_rewrite(data, "", transform)
            out.write(json.dumps(clean, ensure_ascii=False, separators=(",", ":")).encode(codec.encoding))
    return True


def _rewrite_zip(label: str, opener: Opener, budget: _Budget, transform: Transform,
                 entries: list[Entry], sink: Opener, *, top: bool) -> bool:
    with ExitStack() as stack:
        try:
            zin = stack.enter_context(_zip_in(opener, budget))
        except BROKEN:
            entries.append(Entry(label, "broken"))
            return False
        spool = stack.enter_context(tempfile.SpooledTemporaryFile(SPOOL))
        written = top  # верхний архив пишется и пустым: результат задания должен существовать
        with zipfile.ZipFile(spool, "w", zipfile.ZIP_DEFLATED) as zout:
            for info in zin.infolist():
                if info.is_dir():
                    continue
                if _rewrite(f"{label}:{info.filename}", info.filename, partial(zin.open, info), budget, transform,
                            entries, partial(_member, zout, info, transform)):
                    written = True
        if not written:
            return False
        spool.seek(0)
        with sink() as out:
            shutil.copyfileobj(spool, out, BLOCK)
    return True


def _member(zout: zipfile.ZipFile, info: zipfile.ZipInfo, transform: Transform) -> IO[bytes]:
    # Имя меняется, только когда член пишется: имя пропущенного файла не считается и не попадает в таблицу.
    # Дата из исходника, а не текущая: два прогона дают один и тот же архив байт в байт.
    member = zipfile.ZipInfo(transform(NAME, info.filename), info.date_time)
    member.compress_type = zipfile.ZIP_DEFLATED
    return zout.open(member, "w")


def _gzip(sink: Opener) -> Opener:
    @contextmanager
    def open_() -> Iterator[IO[bytes]]:
        # Без имени и времени в заголовке: имя может быть настоящим, время ломает повторяемость.
        with sink() as out, gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0) as stream:
            yield stream  # type: ignore[misc]
    return open_


def _rewrite_lines(raw: IO[bytes], out: IO[bytes], encoding: str, transform: Transform) -> None:
    reader = io.TextIOWrapper(raw, encoding=encoding, newline="")
    writer = io.TextIOWrapper(out, encoding=encoding, newline="")
    try:
        for line in reader:
            writer.write(transform("", line))
        writer.flush()
    finally:
        writer.detach()
        reader.detach()


def _json_rewrite(value: Any, key: str, transform: Transform) -> Any:
    if isinstance(value, dict):
        address = _octets(key, value)
        if address is not None:
            try:
                packed = IPv4Address(transform(OCTETS, address)).packed
            except ValueError:
                return value
            return {**value, "value": base64.b64encode(packed).decode()}
        return {transform(KEY, k): _json_rewrite(v, k, transform) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_rewrite(v, key, transform) for v in value]
    if isinstance(value, str):
        return transform(key, value)
    return value
