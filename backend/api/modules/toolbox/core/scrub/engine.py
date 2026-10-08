"""Ход очистки (спека §3, §5): скан находок, замена включённых, самопроверка результата, обратный перевод.

Без FastAPI и SQLAlchemy: словари приходят в `Ctx`, таблица соответствий — через протокол `Aliases`.
"""
from __future__ import annotations

import dataclasses
import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from api.modules.toolbox.core.scrub.detectors import KEYWORD_NAME, VERSION_KEY, detect
from api.modules.toolbox.core.scrub.files import Entry, rewrite, walk
from api.modules.toolbox.core.scrub.rules import compose, keep_case, replace
from api.modules.toolbox.core.scrub.types import (
    STORED_KINDS,
    Aliases,
    Ctx,
    Finding,
    Match,
    value_key,
)

#: Контекстов на находку и символов в контексте (спека §3).
CONTEXTS = 3
CONTEXT = 80
#: Насколько далеко от адреса искать version/build: «agent build 7.2.3.4» — номер сборки.
VERSION_NEAR = 40
#: Имена, которые после включения ищутся и голыми: jdoe из CORP\jdoe — та же учётка и в «user jdoe».
BARE = {"host": "hosts", "user": "users", "domain": "domains"}
#: Границы значения в самопроверке и псевдонима в обратном переводе — как у словаря: всё, кроме букв
#: и цифр («-», «_», «.» — тоже). Так host-0001_notes и DOM1_backup переводятся обратно, «-500» за
#: псевдонимом SID (RID) — граница, а word-0001 внутри word-00012 — нет.
EDGE_BEFORE, EDGE_AFTER = r"(?<![^\W_])", r"(?![^\W_])"


class VerifyError(Exception):
    """Результат не прочитан целиком: проверка не может сказать, что он чист."""


@dataclass(slots=True)
class ScanResult:
    findings: list[Finding]
    entries: list[Entry]
    chunks: int


def _keyed(ctx: Ctx) -> Callable[[str], Ctx]:
    """Ctx с ключом JSON куска; ключей в выгрузке немного — копии кешируются."""
    cache: dict[str, Ctx] = {}

    def get(json_key: str) -> Ctx:
        if json_key not in cache:
            cache[json_key] = dataclasses.replace(ctx, json_key=json_key)
        return cache[json_key]
    return get


def _parts(m: Match) -> tuple[tuple[str, str], ...]:
    # У SID часть — RID: он не значение, псевдоним получает SID домена целиком.
    if m.kind == "sid" or not m.parts:
        return ((m.kind, m.value),)
    return m.parts


def _versionlike(m: Match, text: str, json_key: str) -> bool:
    if m.kind != "ip4":
        return False
    near = text[max(0, m.start - VERSION_NEAR):m.end + VERSION_NEAR]
    return bool(VERSION_KEY.search(near) or VERSION_KEY.search(json_key))


def _context(text: str, start: int, end: int) -> str:
    begin = max(0, start - max(0, CONTEXT - (end - start)) // 2)
    return text[begin:begin + CONTEXT].strip()


def scan(source: Path, ctx: Ctx, aliases: Aliases, *,
         progress: Callable[[int, str], None] | None = None) -> ScanResult:
    """Находка на каждое (kind, value_key): число вхождений, до 3 контекстов, первый файл, псевдоним
    (из таблицы, иначе слово владельца, иначе кандидат без записи). Без галочки — значения, все вхождения
    которых найдены только авто-поиском или похожи на номер версии."""
    found: dict[tuple[str, str], Finding] = {}
    manual: set[tuple[str, str]] = set()  # хоть раз найдено не авто-поиском
    plain: set[tuple[str, str]] = set()  # хоть раз — не авто и не похоже на версию
    named = {word.lower(): alias for word, alias in ctx.words.items() if alias}
    keyed = _keyed(ctx)
    entries: list[Entry] = []
    chunks = 0
    for entry, pieces in walk(source):
        entries.append(entry)
        for json_key, text in pieces:
            chunks += 1
            for m in detect(text, keyed(json_key)):
                doubtful = m.auto or _versionlike(m, text, json_key)
                for kind, value in _parts(m):
                    key = (kind, value_key(kind, value))
                    finding = found.get(key)
                    if finding is None:
                        alias = (aliases.get(*key) or (named.get(key[1]) if kind == "word" else None)
                                 or aliases.propose(kind, value, key[1]))
                        finding = found[key] = Finding(kind, value, key[1], alias, first_file=entry.path)
                    finding.count += 1
                    if len(finding.contexts) < CONTEXTS:
                        finding.contexts.append(_context(text, m.start, m.end))
                    if not m.auto:
                        manual.add(key)
                    if not doubtful:
                        plain.add(key)
        if progress is not None:
            progress(len(entries), entry.path)
    for key, finding in found.items():
        finding.auto = key not in manual
        finding.checked = key in plain
    return ScanResult(list(found.values()), entries, chunks)


def _with_checked(ctx: Ctx, findings: list[Finding]) -> Ctx:
    """Включённые хосты, учётки и домены добавлены в словари: их голые вхождения — тоже замена."""
    extra = {
        field: getattr(ctx, field) | {f.value_key for f in findings if f.checked and f.kind == kind}
        for kind, field in BARE.items()
    }
    return dataclasses.replace(ctx, **extra)


def apply(source: Path, target: Path, findings: list[Finding], ctx: Ctx,
          aliases: Aliases) -> tuple[list[Entry], dict[str, int]]:
    """Замена включённых находок их псевдонимами; составные собираются из псевдонимов частей. Новые пары
    встретившихся значений — в таблицу (без секретов). Счётчики — вхождения по kind."""
    chosen = {(f.kind, f.value_key): f.alias for f in findings if f.checked}
    counts: Counter[str] = Counter()
    met: dict[tuple[str, str], str] = {}  # (kind, key) → как встретилось впервые
    keyed = _keyed(_with_checked(ctx, findings))

    def part(kind: str, value: str) -> str:
        key = (kind, value_key(kind, value))
        alias = chosen.get(key)
        if alias is None:  # без галочки — как было
            return value
        counts[kind] += 1
        met.setdefault(key, value)
        return alias

    def transform(json_key: str, text: str) -> str:
        return replace(text, detect(text, keyed(json_key)), lambda m: compose(m, part))

    entries = rewrite(source, target, transform)
    aliases.commit([(kind, key, real, chosen[(kind, key)]) for (kind, key), real in met.items()
                    if kind in STORED_KINDS and aliases.get(kind, key) is None])
    return entries, dict(counts)


def verify(target: Path, findings: list[Finding], ctx: Ctx) -> list[Finding]:
    """Повторный поиск по результату — теми же детекторами и дословно по включённым значениям (спека §3.4):
    включённые значения, встретившиеся снова, — с числом и первым файлом.

    Закрыта по умолчанию: нет результата, или в нём не прочитанный как текст файл (а rewrite пишет только
    текст) — `VerifyError`, а не «чисто».
    """
    if not target.is_file():
        raise VerifyError(f"{target.name}: результата нет")
    wanted = {(f.kind, f.value_key): f for f in findings if f.checked}
    literal = _literal(wanted)
    mask = _own_aliases(wanted)
    left: dict[tuple[str, str], Finding] = {}
    keyed = _keyed(_with_checked(ctx, findings))

    def leftover(key: tuple[str, str], path: str) -> None:
        origin = wanted.get(key)
        if origin is None:
            return
        if key not in left:
            left[key] = Finding(key[0], origin.value, key[1], origin.alias, first_file=path)
        left[key].count += 1

    for entry, pieces in walk(target):
        if entry.kind in ("broken", "skipped"):
            raise VerifyError(f"{entry.path}: не прочитан как текст ({entry.kind})")
        for json_key, text in pieces:
            if mask is not None:
                # Свои псевдонимы и метки секретов — пробелами той же длины: «user» внутри user-0001,
                # «example» внутри dom1.example — не остаток.
                text = mask.sub(lambda m: " " * len(m.group(0)), text)
            spans: list[tuple[int, int, set[tuple[str, str]]]] = []
            for m in detect(text, keyed(json_key)):
                keys = {(kind, value_key(kind, value)) for kind, value in _parts(m)}
                spans.append((m.start, m.end, keys))
                for kind, value in _parts(m):
                    leftover((kind, value_key(kind, value)), entry.path)
            if literal is None:
                continue
            pattern, spellings = literal
            for hit in pattern.finditer(text):
                key = _spelled(spellings, hit.group(0))
                # Ключевое слово перед «=»/«:» — не значение, даже если пароль с ним совпал.
                name = KEYWORD_NAME.match(text, hit.start())
                if name is not None and name.end(1) == hit.end():
                    continue
                # Второй раз не считается только то, что детектор уже посчитал под тем же ключом.
                if not any(s <= hit.start() and hit.end() <= e and key in keys for s, e, keys in spans):
                    leftover(key, entry.path)
    return list(left.values())


def _spelled(spellings: dict[str, tuple[str, str]], found: str) -> tuple[str, str]:
    key = spellings.get(found.casefold())
    if key is not None:
        return key
    # IGNORECASE сопоставляет и то, что casefold сворачивает иначе (редкие буквы): ищется то написание,
    # под которое попало найденное.
    return next(k for s, k in spellings.items() if re.fullmatch(re.escape(s), found, re.IGNORECASE))


def _own_aliases(wanted: dict[tuple[str, str], Finding]) -> re.Pattern[str] | None:
    """Всё, что apply пишет сам: псевдонимы включённых находок (составные — из них же) и метки секретов.
    Псевдоним, совпавший с настоящим значением, не маскируется: иначе он спрятал бы настоящий остаток."""
    reals = {s.casefold() for f in wanted.values() for s in (f.value, f.value_key)}
    own = [f for f in wanted.values() if f.alias.casefold() not in reals]
    if not own:
        return None
    # Слово меняется и внутри других слов (password → password-0001), его псевдоним — тоже без границ.
    alternatives = "|".join(
        re.escape(f.alias) if f.kind == "word" else f"{EDGE_BEFORE}{re.escape(f.alias)}{EDGE_AFTER}"
        for f in sorted(own, key=lambda f: len(f.alias), reverse=True)
    )
    return re.compile(alternatives, re.IGNORECASE)


def _literal(wanted: dict[tuple[str, str], Finding]) -> tuple[re.Pattern[str], dict[str, tuple[str, str]]] | None:
    """Все включённые значения дословно, без учёта регистра: детектор мог не узнать значение вне
    его привычного окружения (голая учётка без словаря, имя хоста внутри имени файла)."""
    keys: dict[str, tuple[str, str]] = {}
    for key, finding in wanted.items():
        for spelling in (finding.value, finding.value_key):
            keys.setdefault(spelling.casefold(), key)
    if not keys:
        return None
    alternatives = "|".join(re.escape(v) for v in sorted(keys, key=len, reverse=True))
    return re.compile(f"{EDGE_BEFORE}(?:{alternatives}){EDGE_AFTER}", re.IGNORECASE), keys


def reverse(text: str, pairs: Iterable[tuple[str, str]]) -> tuple[str, int]:
    """Пары (псевдоним, настоящее): псевдоним → настоящее, длинные раньше коротких, без учёта регистра,
    целыми словами с границами словаря: host-0001_notes переводится, word-0001 внутри word-00012 — нет."""
    table: dict[str, tuple[str, str]] = {}
    for alias, real in pairs:
        table.setdefault(alias.lower(), (alias, real))
    if not table:
        return text, 0
    alternatives = "|".join(re.escape(a) for a in sorted(table, key=len, reverse=True))
    pattern = re.compile(f"{EDGE_BEFORE}(?:{alternatives}){EDGE_AFTER}", re.IGNORECASE)
    replaced = 0

    def back(m: re.Match[str]) -> str:
        nonlocal replaced
        replaced += 1
        alias, real = table[m.group(0).lower()]
        # Псевдоним в написании таблицы — значение как встретилось впервые: word-0001 → Ivanov, а не ivanov.
        return real if m.group(0) == alias else keep_case(m.group(0), real)

    return pattern.sub(back, text), replaced
