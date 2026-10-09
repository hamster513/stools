"""Ход очистки (спека §3, §5): скан находок, замена включённых, самопроверка результата, обратный перевод.

Без FastAPI и SQLAlchemy: словари приходят в `Ctx`, таблица соответствий — через протокол `Aliases`.
"""
from __future__ import annotations

import dataclasses
import re
from bisect import bisect_right
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
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


def _placed(m: Match, text: str) -> list[tuple[str, str, int, int]]:
    """Части совпадения с их местом: составное — две части по краям (host.domain, DOM\\user,
    user@domain), значения частей — дословные куски текста."""
    parts = _parts(m)
    if len(parts) == 1:
        (kind, value), = parts
        return [(kind, value, m.start, m.end)]
    (first, head), (last, tail) = parts
    placed = [(first, head, m.start, m.start + len(head)), (last, tail, m.end - len(tail), m.end)]
    # Новая форма составного должна упасть здесь, а не молча проверять чужое место.
    for _, value, start, end in placed:
        assert text[start:end].lower() == value.lower(), (m, text[start:end])
    return placed


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
                version = _versionlike(m, text, json_key)
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
                    # Часть авто-составного, которая есть в словаре (msk1 из msk1.other.org), — не авто.
                    auto = m.auto and not (kind in BARE and key[1] in getattr(ctx, BARE[kind]))
                    if not auto:
                        manual.add(key)
                    if not (auto or version):
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
    own = _own_aliases(wanted)
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
            # «user» внутри user-0001, «example» внутри dom1.example — не остаток; bankov вокруг
            # псевдонима Bank выходит за его пределы — остаток.
            inside = _Inside([pattern.finditer(text) for pattern in own])
            spans: list[tuple[int, int, tuple[str, str]]] = []
            for m in detect(text, keyed(json_key)):
                # Части составного — каждая на своём месте: в mail.dom2.example домен «example» лежит
                # внутри своего псевдонима dom2.example, а совпадение целиком — нет.
                for kind, value, start, end in _placed(m, text):
                    if inside(start, end):
                        continue
                    key = (kind, value_key(kind, value))
                    spans.append((start, end, key))
                    leftover(key, entry.path)
            if literal is None:
                continue
            pattern, spellings = literal
            for hit in pattern.finditer(text):
                if inside(hit.start(), hit.end()):
                    continue
                key = _spelled(spellings, hit.group(0))
                # Ключевое слово перед «=»/«:» — не значение, даже если пароль с ним совпал.
                name = KEYWORD_NAME.match(text, hit.start())
                if name is not None and name.end(1) == hit.end():
                    continue
                # Второй раз не считается только то, что детектор уже посчитал под тем же ключом.
                if not any(s <= hit.start() and hit.end() <= e and key == k for s, e, k in spans):
                    leftover(key, entry.path)
    return list(left.values())


def _spelled(spellings: dict[str, tuple[str, str]], found: str) -> tuple[str, str]:
    key = spellings.get(found.casefold())
    if key is not None:
        return key
    # IGNORECASE сопоставляет и то, что casefold сворачивает иначе (редкие буквы): ищется то написание,
    # под которое попало найденное.
    return next(k for s, k in spellings.items() if re.fullmatch(re.escape(s), found, re.IGNORECASE))


class _Inside:
    """Лежит ли отрезок целиком внутри одного из своих псевдонимов. Совпадения каждого шаблона
    не пересекаются и идут по порядку — ближайшее слева находится делением пополам."""

    def __init__(self, found: list[Iterator[re.Match[str]]]) -> None:
        self.spans = [[m.span() for m in matches] for matches in found]
        self.starts = [[start for start, _ in spans] for spans in self.spans]

    def __call__(self, start: int, end: int) -> bool:
        for spans, starts in zip(self.spans, self.starts, strict=True):
            i = bisect_right(starts, start)
            if i and spans[i - 1][1] >= end:
                return True
        return False


def _own_aliases(wanted: dict[tuple[str, str], Finding]) -> list[re.Pattern[str]]:
    """Всё, что apply пишет сам: псевдонимы включённых находок (составные — из них же) и метки секретов.
    Псевдоним, совпавший с настоящим значением, не в счёт: иначе он спрятал бы настоящий остаток.

    Границы — общие на всю альтернацию, а не у каждой альтернативы: так regex ищет по общим префиксам
    (на 2000 псевдонимах — десятки секунд на мегабайт против сотых)."""
    reals = {s.casefold() for f in wanted.values() for s in _spellings(f)}
    own = [f for f in wanted.values() if f.alias.casefold() not in reals]
    patterns = []
    # Слово меняется и внутри других слов (password → password-0001), его псевдоним — тоже без границ.
    for words, before, after in ((False, EDGE_BEFORE, EDGE_AFTER), (True, "", "")):
        aliases = sorted({f.alias for f in own if (f.kind == "word") == words}, key=len, reverse=True)
        if aliases:
            alternatives = "|".join(re.escape(a) for a in aliases)
            patterns.append(re.compile(f"{before}(?:{alternatives}){after}", re.IGNORECASE))
    return patterns


def _spellings(finding: Finding) -> tuple[str, ...]:
    """Как включённое значение может встретиться дословно: как найдено, по ключу и — у хоста с точками —
    коротким именем (srv-db01 из srv-db01.corp.test): если составное разрезано не там, голое короткое
    имя — тот же хост и остаток."""
    if finding.kind == "host" and "." in finding.value_key:
        return finding.value, finding.value_key, finding.value_key.split(".", 1)[0]
    return finding.value, finding.value_key


def _literal(wanted: dict[tuple[str, str], Finding]) -> tuple[re.Pattern[str], dict[str, tuple[str, str]]] | None:
    """Все включённые значения дословно, без учёта регистра: детектор мог не узнать значение вне
    его привычного окружения (голая учётка без словаря, имя хоста внутри имени файла)."""
    keys: dict[str, tuple[str, str]] = {}
    for key, finding in wanted.items():
        for spelling in _spellings(finding):
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
