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
#: Шаг отчёта о ходе: поиск идёт порядка секунд на мегабайт, и отметка раз в мегабайт была бы редкой
#: для «не подвисло ли»; запись в базу всё равно реже — её прореживает вызывающий.
STEP = MB // 4
#: Вложенный архив меньше этого держится в памяти, больше — во временном файле.
SPOOL = 64 * MB
#: BOM снимается при чтении и ставится обратно при записи: кодировки ниже — без BOM. Средствами
#: TextIOWrapper нельзя: в поток записи члена zip (не перематывается) он BOM не пишет.
BOMS = {b"\xef\xbb\xbf": "utf-8", b"\xff\xfe": "utf-16-le", b"\xfe\xff": "utf-16-be"}
#: Так рвётся повреждённый архив или чтение: такой файл — запись `broken`, в результат не идёт.
#: RuntimeError — зашифрованный член zip без пароля, NotImplementedError — неизвестное сжатие (Deflate64).
BROKEN = (OSError, EOFError, zipfile.BadZipFile, zlib.error, RuntimeError, NotImplementedError)
#: Ключи кусков, которые не значения JSON: имя файла в архиве и имя ключа JSON.
NAME = "__name__"
KEY = "__key__"
OCTETS = "octets"

Opener = Callable[[], AbstractContextManager[IO[bytes]]]
Chunks = Iterator[tuple[str, str]]
Transform = Callable[[str, str], str]
OnProgress = Callable[["Progress"], None]


class UnpackLimit(Exception):
    """Распаковано больше MAX_UNPACKED."""


@dataclass(slots=True)
class Entry:
    path: str  # «архив.zip:внутри/файл.json»
    # json | text | skipped (не текст) | broken (ошибка чтения или повреждённый архив)
    kind: str


@dataclass(frozen=True, slots=True)
class Progress:
    """Ход обхода — чтобы человек видел, что задание не подвисло, даже внутри одного большого файла."""

    path: str  # текущая запись
    entries_done: int
    #: Известно заранее для простого файла (1) и zip без вложенных архивов (число файлов); иначе None.
    entries_total: int | None
    #: Пройдено байт исходного файла верхнего уровня: его размер известен — это честная полоса.
    source_pos: int
    unpacked: int
    chunks: int


class _Budget:
    """Распакованный объём (потолок MAX_UNPACKED) и ход обхода для `on_progress`.

    Позиция берётся из `tell()` исходного файла верхнего уровня — пока куски идут из потока (текст
    построчно). JSON разбирается целиком, и файл к началу кусков уже дочитан: тогда позиция внутри
    записи — доля пройденного текста её кусков. Пока файл распознаётся и проверяется кодировка (он
    читается целиком до кусков), позиция стоит: иначе полоса дошла бы до конца раньше работы.
    """

    def __init__(self, source: Path, on_progress: OnProgress | None = None) -> None:
        self.used = 0
        self._source = source
        self._on_progress = on_progress
        self._total = _count(source) if on_progress is not None else None
        self._file: IO[bytes] | None = None
        self._closed_at = 0  # где был исходный файл, когда его закрыли
        self._pos = 0
        #: (позиция в начале записи, в конце, объём текста кусков) — пока куски идут не из потока.
        self._span: tuple[int, int, int] | None = (0, 0, 0)
        self._weight = 0
        self._since = 0  # прочитано с прошлого отчёта
        self._path = ""
        self._done = 0
        self._chunks = 0

    def add(self, size: int) -> None:
        self.used += size
        if self.used > MAX_UNPACKED:
            raise UnpackLimit(f"распакованный размер больше лимита ({MAX_UNPACKED // MB} МБ)")
        self._tick(size, sample=False)

    @contextmanager
    def open(self) -> Iterator[IO[bytes]]:
        """Исходный файл верхнего уровня; его позиция — ход обхода."""
        with self._source.open("rb") as f:
            self._file = f
            try:
                yield f
            finally:
                self._closed_at = f.tell()
                self._file = None

    def begin(self, path: str) -> None:
        self._path = path

    def stream(self) -> None:
        """Куски записи идут из потока: позиция — по tell()."""
        self._span = None

    def in_memory(self, data: Any) -> None:
        """Запись (JSON) прочитана целиком: позиция идёт от прежней до нынешней по доле текста кусков."""
        if self._on_progress is None:
            return  # без отчёта лишний проход по разобранному JSON не нужен
        total = sum(len(text) for _, text in _json_chunks(data, ""))
        self._span = (self._pos, max(self._pos, self._tell()), total)
        self._weight = 0

    def feed(self, text: str) -> None:
        self._chunks += 1
        self._weight += len(text)
        self._tick(len(text), sample=True)

    def metered(self, chunks: Chunks) -> Chunks:
        for chunk in chunks:
            self.feed(chunk[1])
            yield chunk

    def entry_done(self) -> None:
        self._done += 1
        if self._total is not None and self._done > self._total:
            self._total = None  # вложенный архив без расширения .zip: заранее посчитать не вышло
        self._pos = max(self._pos, self._tell())
        self._span = (self._pos, self._pos, 0)
        self._report()

    def finish(self) -> None:
        """Обход кончился — исходный файл пройден целиком (хвост zip — каталог, а не записи)."""
        try:
            self._pos = max(self._pos, self._source.stat().st_size)
        except OSError:
            pass
        self._report()

    def _tell(self) -> int:
        return self._file.tell() if self._file is not None else self._closed_at

    def _tick(self, size: int, *, sample: bool) -> None:
        if self._on_progress is None:
            return
        self._since += size
        if self._since < STEP:
            return
        self._since = 0
        if sample:
            if self._span is None:
                self._pos = max(self._pos, self._tell())
            else:
                start, end, total = self._span
                if total:
                    self._pos = max(self._pos, start + (end - start) * min(self._weight, total) // total)
        self._report()

    def _report(self) -> None:
        if self._on_progress is not None:
            self._on_progress(Progress(self._path, self._done, self._total, self._pos, self.used, self._chunks))


_TEXT = object()  # вместо разобранного JSON: файл читается построчно


class _Codec(NamedTuple):
    bom: bytes
    encoding: str


def walk(source: Path, on_progress: OnProgress | None = None) -> Iterator[tuple[Entry, Chunks]]:
    """Для каждого файла (включая лежащие в zip, во вложенных zip, в .gz) — запись и итератор кусков
    (json_key, text). Итератор кусков читается до следующего шага `walk`: он читает из открытого архива.

    Имена файлов в архиве — куски с ключом `__name__`, имена ключей JSON — с `__key__`, двоичный адрес
    `octets` — кусок с адресом текстом. Распаковано больше MAX_UNPACKED — `UnpackLimit`.

    `on_progress` — не реже чем через мегабайт прочитанного и на конце каждой записи.
    """
    budget = _Budget(source, on_progress)
    for entry, chunks in _walk(source.name, source.name, budget.open, budget, []):
        budget.begin(entry.path)
        yield entry, budget.metered(chunks)
        # Сюда обход возвращается, когда вызывающий попросил следующую запись: куски этой прочитаны.
        budget.entry_done()
    budget.finish()


def rewrite(source: Path, target: Path, transform: Transform, on_progress: OnProgress | None = None) -> list[Entry]:
    """Тот же обход, но каждый кусок проходит через `transform(json_key, text)` и пишется в результат
    того же типа: zip → zip, .gz → .gz, json → компактный json, текст — той же кодировкой и с теми же
    концами строк. Не-текст в результат не попадает; если весь вход — не текст, `target` не создаётся.
    При `UnpackLimit` недописанный `target` удаляет вызывающий. `on_progress` — как у `walk`."""
    entries: list[Entry] = []
    target.parent.mkdir(parents=True, exist_ok=True)
    budget = _Budget(source, on_progress)

    def metered(json_key: str, text: str) -> str:
        budget.feed(text)
        return transform(json_key, text)

    _rewrite(source.name, source.name, budget.open, budget, metered, entries, lambda: target.open("wb"), top=True)
    budget.finish()
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


def _count(source: Path) -> int | None:
    """Сколько записей даст обход, если это известно заранее: простой файл — одна, zip — по одной на
    файл, если среди них нет вложенных zip; .gz (в нём может быть архив) — неизвестно."""
    kind = _classify(source.name, lambda: source.open("rb"))
    if kind == "gz":
        return None
    if kind != "zip":
        return 1
    try:
        with zipfile.ZipFile(source) as zf:
            names = [info.filename.lower() for info in zf.infolist() if not info.is_dir()]
    except BROKEN:
        return 1  # повреждённый архив — одна запись broken
    return None if any(name.endswith(".zip") for name in names) else len(names)


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
        yield Entry(label, "text"), chain(pending, _lines(opener, codec, budget))
    else:
        budget.in_memory(data)
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


def _lines(opener: Opener, codec: _Codec, budget: _Budget) -> Chunks:
    with opener() as raw:
        budget.stream()
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
    budget.begin(label)
    if isinstance(leaf, str):
        entries.append(Entry(label, leaf))
        budget.entry_done()
        return False
    codec, data = leaf
    with sink() as out:
        out.write(codec.bom)
        if data is _TEXT:
            entries.append(Entry(label, "text"))
            with opener() as raw:
                budget.stream()
                raw.read(len(codec.bom))
                _rewrite_lines(raw, out, codec.encoding, transform)
        else:
            entries.append(Entry(label, "json"))
            budget.in_memory(data)
            clean = _json_rewrite(data, "", transform)
            out.write(json.dumps(clean, ensure_ascii=False, separators=(",", ":")).encode(codec.encoding))
    budget.entry_done()
    return True


def _rewrite_zip(label: str, opener: Opener, budget: _Budget, transform: Transform,
                 entries: list[Entry], sink: Opener, *, top: bool) -> bool:
    with ExitStack() as stack:
        try:
            zin = stack.enter_context(_zip_in(opener, budget))
        except BROKEN:
            budget.begin(label)
            entries.append(Entry(label, "broken"))
            budget.entry_done()
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
