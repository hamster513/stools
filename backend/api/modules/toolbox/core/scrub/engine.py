"""Ход очистки (спека §3, §5): скан находок, замена включённых, самопроверка результата, обратный перевод.

Без FastAPI и SQLAlchemy: словари приходят в `Ctx`, таблица соответствий — через протокол `Aliases`.
"""
from __future__ import annotations

import dataclasses
import re
from bisect import bisect_right
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from dataclasses import asdict, dataclass
from itertools import chain
from pathlib import Path
from typing import Any, Literal

from api.modules.toolbox.core.scrub.detectors import KEYWORD_NAME, VERSION_KEY, detect, key_class
from api.modules.toolbox.core.scrub.files import KEY, NAME, Entry, Progress, rewrite, walk
from api.modules.toolbox.core.scrub.rules import compose, keep_case
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


@dataclass(frozen=True, slots=True)
class Status(Progress):
    """Ход обхода и чем занят движок; `findings` — уникальных значений к этому месту (только скан)."""

    phase: Literal["scan", "apply", "verify"] = "scan"
    findings: int = 0


OnStatus = Callable[[Status], None]


def _relay(progress: OnStatus | None, phase: Literal["scan", "apply", "verify"],
           findings: Callable[[], int] = lambda: 0) -> Callable[[Progress], None] | None:
    if progress is None:
        return None
    return lambda p: progress(Status(**asdict(p), phase=phase, findings=findings()))


@dataclass(slots=True)
class ScanResult:
    findings: list[Finding]
    entries: list[Entry]
    chunks: int


#: Потолок кеша находок: записей и символов текста в ключах. На выгрузке KSC в 13 МБ (686 тыс. кусков,
#: 67 тыс. уникальных) кеш занял ~15 МБ; потолок держит самую большую выгрузку (512 МБ распакованных)
#: в сотнях мегабайт, а не гигабайтах.
MEMO_ENTRIES = 2_000_000
MEMO_CHARS = 64 * 1024 * 1024
#: Кусок из одних цифр не длиннее этого — не находка ни у одного детектора: у адресов есть точки, у имён и
#: слов — буквы, а энтропия строки из n символов не больше log2(n), так что порог Hex detect-secrets (3,0)
#: восемью символами не пройти. Под ключом-паролем цифры — пароль, там пропуска нет.
TRIVIAL_DIGITS = 8
_NONE: list[Match] = []
_NO_KEYS: list[tuple[str, str]] = []
Find = Callable[[str, str], list[Match]]


class Memo:
    """Находки по уникальному тексту куска. В выгрузках одни и те же строки (имена ключей, перечисления,
    пути, имена хостов) повторяются миллионы раз, а находки зависят только от текста и класса ключа JSON
    (`key_class`) — поэтому кусок ищется один раз. Живёт один проход или одно задание: apply и verify идут
    с одним ctx и делят кеш, ctx другого содержания его очищает. Полный кеш больше не растёт, поиск идёт
    мимо него. `enabled=False` — медленный путь (каждый кусок через `detect`), для сверки в тестах."""

    def __init__(self, *, enabled: bool = True, entries: int = MEMO_ENTRIES, chars: int = MEMO_CHARS) -> None:
        self.enabled = enabled
        self._entries = entries
        self._chars = chars
        self._ctx: Ctx | None = None
        self._cache: dict[str, dict[str, list[Match]]] = {}  # класс ключа → текст → находки
        self._count = 0
        self._size = 0

    @property
    def entries(self) -> int:
        return self._count

    def bind(self, ctx: Ctx) -> Find:
        """Поиск `find(json_key, text)` для прохода с этим ctx."""
        if ctx != self._ctx:
            self._ctx = ctx
            self._cache = {}
            self._count = self._size = 0
        # Пустой кусок, пробелы и короткие цифры не ищутся вовсе — если в словарях нет имени или слова из
        # одних цифр или пробелов (слово ищется как часть строки, имя — как целая метка).
        skip_trivial = not any(n.isdigit() or n.isspace() for n in chain(ctx.hosts, ctx.users, ctx.domains, ctx.words))
        keyed: dict[str, tuple[dict[str, list[Match]], Ctx, bool]] = {}
        enabled = self.enabled

        def find(json_key: str, text: str) -> list[Match]:
            got = keyed.get(json_key)
            if got is None:
                cls = key_class(json_key)
                # Имена ключей JSON и файлов в архиве идут обычным путём, без пропуска.
                plain = skip_trivial and cls == "" and json_key not in (KEY, NAME)
                got = keyed[json_key] = (self._cache.setdefault(cls, {}), dataclasses.replace(ctx, json_key=cls), plain)
            cache, kctx, plain = got
            if not enabled:
                return detect(text, kctx)
            if plain and (not text or text.isspace() or (text.isdigit() and len(text) <= TRIVIAL_DIGITS)):
                return _NONE
            found = cache.get(text)
            if found is None:
                found = detect(text, kctx) or _NONE
                if self._count < self._entries and self._size + len(text) <= self._chars:
                    cache[text] = found
                    self._count += 1
                    self._size += len(text)
            return found
        return find


def _parts(m: Match) -> tuple[tuple[str, str], ...]:
    # У SID часть — RID: он не значение, псевдоним получает SID домена целиком.
    if m.kind == "sid" or not m.parts:
        return ((m.kind, m.value),)
    return m.parts


def _placed(m: Match, text: str, path: str) -> list[tuple[str, str, int, int]]:
    """Части совпадения с их местом: составное — две части по краям (host.domain, DOM\\user,
    user@domain), значения частей — дословные куски текста."""
    parts = _parts(m)
    if len(parts) == 1:
        (kind, value), = parts
        return [(kind, value, m.start, m.end)]
    (first, head), (last, tail) = parts
    placed = [(first, head, m.start, m.start + len(head)), (last, tail, m.end - len(tail), m.end)]
    # Новая форма составного должна упасть здесь, а не молча проверять чужое место. Без значения в тексте
    # ошибки: он попадает в job.error, который видят все роли.
    for _, value, start, end in placed:
        if text[start:end].lower() != value.lower():
            raise VerifyError(f"{path}: составное совпадение не на своём месте")
    return placed


def _versionlike(m: Match, text: str, json_key: str) -> bool:
    if m.kind != "ip4":
        return False
    near = text[max(0, m.start - VERSION_NEAR):m.end + VERSION_NEAR]
    return bool(VERSION_KEY.search(near) or VERSION_KEY.search(json_key))


def _context(text: str, start: int, end: int) -> str:
    begin = max(0, start - max(0, CONTEXT - (end - start)) // 2)
    return text[begin:begin + CONTEXT].strip()


def scan(source: Path, ctx: Ctx, aliases: Aliases, *, progress: OnStatus | None = None,
         memo: Memo | None = None) -> ScanResult:
    """Находка на каждое (kind, value_key): число вхождений, до 3 контекстов, первый файл, псевдоним
    (из таблицы, иначе слово владельца, иначе кандидат без записи). Без галочки — значения, все вхождения
    которых найдены только авто-поиском или похожи на номер версии."""
    found: dict[tuple[str, str], Finding] = {}
    manual: set[tuple[str, str]] = set()  # хоть раз найдено не авто-поиском
    plain: set[tuple[str, str]] = set()  # хоть раз — не авто и не похоже на версию
    named = {word.lower(): alias for word, alias in ctx.words.items() if alias}
    find = (memo if memo is not None else Memo()).bind(ctx)
    entries: list[Entry] = []
    chunks = 0
    for entry, pieces in walk(source, _relay(progress, "scan", lambda: len(found))):
        entries.append(entry)
        for json_key, text in pieces:
            chunks += 1
            for m in find(json_key, text):
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


Key = tuple[str, str]
#: Дословный поиск включённых значений: regex и ключ по найденному написанию.
Lookup = tuple[re.Pattern[str], dict[str, Key]]
#: Дословное вхождение: отрезок и ключ включённого значения.
Hit = tuple[int, int, Key]


def _targets(findings: list[Finding]) -> tuple[dict[Key, Finding], dict[Key, Key]]:
    """Включённые находки по ключу и короткие имена хостов с точкой (msk1 из msk1.sub) → ключ хоста.
    Голое короткое имя — тот же хост, если оно не находка само по себе: тогда решает его собственная галочка."""
    wanted = {(f.kind, f.value_key): f for f in findings if f.checked}
    known = {(f.kind, f.value_key) for f in findings}
    shorts = {("host", short): key for key, f in wanted.items()
              if (short := _short(f)) is not None and ("host", short) not in known}
    return wanted, shorts


def _short(finding: Finding) -> str | None:
    """Короткое имя хоста с точкой (srv-db01 из srv-db01.corp.test, msk1 из msk1.sub): если составное
    разрезано не там, голое короткое имя — тот же хост."""
    if finding.kind == "host" and "." in finding.value_key:
        return finding.value_key.split(".", 1)[0]
    return None


def _hits(literal: Lookup, text: str, json_key: str) -> list[Hit]:
    """Дословные вхождения включённых значений в куске — одни и те же для замены и самопроверки: что
    самопроверка нашла бы дословно, замена уже заменила, а что замена оставляет намеренно, самопроверка не
    считает."""
    pattern, spellings = literal
    # Под ключами version/build адрес — номер версии: find_ip4 его не ищет (спека §1), apply не меняет.
    version = VERSION_KEY.search(json_key) is not None
    found: list[Hit] = []
    for hit in pattern.finditer(text):
        key = _spelled(spellings, hit.group(0))
        if version and key[0] == "ip4":
            continue
        # Ключевое слово перед «=»/«:» — не значение, даже если пароль с ним совпал.
        name = KEYWORD_NAME.match(text, hit.start())
        if name is not None and name.end(1) == hit.end():
            continue
        found.append((hit.start(), hit.end(), key))
    return found


def _render(text: str, segments: list[tuple[int, int, str, str]]) -> str:
    """Один проход слева направо по непересекающимся отрезкам (start, end, kind, псевдоним); вставленное
    повторно не ищется. Псевдоним секрета — метка <secret-xxxxxxxx>, регистр значения в неё не переносится."""
    out: list[str] = []
    pos = 0
    for start, end, kind, alias in sorted(segments):
        out += (text[pos:start], alias if kind == "secret" else keep_case(text[start:end], alias))
        pos = end
    out.append(text[pos:])
    return "".join(out)


#: Что заменено в куске: kind, ключ включённого значения, настоящее значение для таблицы.
Replaced = tuple[str, Key, str]


def apply(source: Path, target: Path, findings: list[Finding], ctx: Ctx, aliases: Aliases, *,
          progress: OnStatus | None = None, memo: Memo | None = None) -> tuple[list[Entry], dict[str, int]]:
    """Замена включённых находок их псевдонимами; составные собираются из псевдонимов частей. Сверх
    детекторов включённые значения меняются и дословно — там, где детектор их не узнал или где они лежат
    внутри совпадения без галочки (NetBIOS-домен в имени снятого авто-хоста site-corp): ровно там же их
    нашла бы самопроверка. Новые пары встретившихся значений — в таблицу (без секретов). Счётчики —
    вхождения по kind. `memo` — общий с самопроверкой того же задания: словари у них одни."""
    wanted, shorts = _targets(findings)
    chosen = {key: f.alias for key, f in wanted.items()}
    literal = _literal(wanted, shorts)
    counts: Counter[str] = Counter()
    met: dict[Key, str] = {}  # (kind, key) → как встретилось впервые
    memo = memo if memo is not None else Memo()
    find = memo.bind(_with_checked(ctx, findings))
    # Результат куска зависит только от его текста и ключа — как и находки, считается один раз на
    # уникальный текст: дословный поиск по всем включённым значениям — regex с тысячами альтернатив, на
    # повторах он стоил больше самих детекторов.
    done: dict[tuple[str, str], tuple[str, list[Replaced]]] = {}

    def real(key: Key, found: str) -> str:
        # Значение для таблицы — как встретилось; короткое имя хоста — хост целиком (msk1 → msk1.sub).
        return found if value_key(key[0], found) == key[1] else wanted[key].value

    def scrub(json_key: str, text: str) -> tuple[str, list[Replaced]]:
        replaced: list[Replaced] = []

        def resolve(kind: str, value: str) -> str | None:
            key = (kind, value_key(kind, value))
            key = shorts.get(key, key)
            alias = chosen.get(key)
            if alias is not None:
                replaced.append((kind, key, real(key, value)))
            return alias

        def literally(value: str) -> str:
            # Часть без галочки — как была, но включённые значения внутри неё меняются дословно. Края части —
            # разделитель составного или граница слова, так что вхождения те же, что в целом куске.
            hits = _hits(literal, value, json_key) if literal is not None else []
            if not hits:
                return value
            replaced.extend((k[0], k, real(k, value[s:e])) for s, e, k in hits)
            return _render(value, [(s, e, k[0], chosen[k]) for s, e, k in hits])

        parts: dict[tuple[str, str], str | None] = {}  # части текущего совпадения → псевдоним, None без галочки

        def piece(kind: str, value: str) -> str:
            return parts[(kind, value)] or literally(value)

        segments: list[tuple[int, int, str, str]] = []
        kept: list[tuple[int, int]] = []
        for m in find(json_key, text):
            parts = {part: resolve(*part) for part in _parts(m)}
            if all(alias is None for alias in parts.values()):
                continue  # без галочки — как было; включённые значения внутри — дословно, ниже
            kept.append((m.start, m.end))
            segments.append((m.start, m.end, m.kind, compose(m, piece)))
        if literal is not None:
            # Дословные вхождения вне заменяемых отрезков: детектор их не узнал (учётка в имени файла) или
            # отдал место совпадению без галочки. Внутри заменяемого — исчезнут вместе с ним. Оба списка
            # по возрастанию start и без пересечений внутри себя — одна сверка слиянием.
            i = 0
            for start, end, key in _hits(literal, text, json_key):
                while i < len(kept) and kept[i][1] <= start:
                    i += 1
                if i < len(kept) and kept[i][0] < end:
                    continue
                segments.append((start, end, key[0], chosen[key]))
                replaced.append((key[0], key, real(key, text[start:end])))
        return (_render(text, segments) if segments else text), replaced

    def transform(json_key: str, text: str) -> str:
        got = done.get((json_key, text)) if memo.enabled else None
        if got is None:
            got = scrub(json_key, text)
            if memo.enabled and len(done) < MEMO_ENTRIES:
                done[(json_key, text)] = got
        out, replaced = got
        for kind, key, value in replaced:
            counts[kind] += 1
            met.setdefault(key, value)
        return out

    entries = rewrite(source, target, transform, _relay(progress, "apply"))
    aliases.commit([(kind, key, value, chosen[(kind, key)]) for (kind, key), value in met.items()
                    if kind in STORED_KINDS and aliases.get(kind, key) is None])
    return entries, dict(counts)


def verify(target: Path, findings: list[Finding], ctx: Ctx, *, progress: OnStatus | None = None,
           memo: Memo | None = None) -> list[Finding]:
    """Повторный поиск по результату — теми же детекторами и дословно по включённым значениям (спека §3.4):
    включённые значения, встретившиеся снова, — с числом и первым файлом.

    Закрыта по умолчанию: нет результата, или в нём не прочитанный как текст файл (а rewrite пишет только
    текст) — `VerifyError`, а не «чисто».
    """
    if not target.is_file():
        raise VerifyError(f"{target.name}: результата нет")
    wanted, shorts = _targets(findings)
    literal = _literal(wanted, shorts)
    own = _own_aliases(wanted, shorts)
    left: dict[tuple[str, str], Finding] = {}
    memo = memo if memo is not None else Memo()
    find = memo.bind(_with_checked(ctx, findings))
    # Остатки в куске зависят только от его текста и ключа — как и находки, считаются один раз на
    # уникальный текст: дословный поиск по всем включённым значениям и по своим псевдонимам — regex с
    # тысячами альтернатив, на повторах он стоил больше самих детекторов.
    seen: dict[tuple[str, str], list[tuple[str, str]]] = {}

    def leftovers(json_key: str, text: str, path: str) -> list[tuple[str, str]]:
        """Ключи включённых значений, оставшихся в куске, по вхождению."""
        found: list[tuple[str, str]] = []
        # «user» внутри user-0001, «example» внутри dom1.example — не остаток; bankov вокруг
        # псевдонима Bank выходит за его пределы — остаток.
        inside = _Inside([pattern.finditer(text) for pattern in own])
        spans: list[tuple[int, int, tuple[str, str]]] = []
        for m in find(json_key, text):
            # Части составного — каждая на своём месте: в mail.dom2.example домен «example» лежит
            # внутри своего псевдонима dom2.example, а совпадение целиком — нет.
            for kind, value, start, end in _placed(m, text, path):
                if inside(start, end):
                    continue
                key = (kind, value_key(kind, value))
                spans.append((start, end, key))
                if key in wanted:
                    found.append(key)
        if literal is None:
            return found
        for start, end, key in _hits(literal, text, json_key):
            if inside(start, end):
                continue
            # Второй раз не считается только то, что детектор уже посчитал под тем же ключом.
            if not any(s <= start and end <= e and key == k for s, e, k in spans):
                found.append(key)
        return found

    for entry, pieces in walk(target, _relay(progress, "verify")):
        if entry.kind in ("broken", "skipped"):
            raise VerifyError(f"{entry.path}: не прочитан как текст ({entry.kind})")
        for json_key, text in pieces:
            keys = seen.get((json_key, text)) if memo.enabled else None
            if keys is None:
                keys = leftovers(json_key, text, entry.path) or _NO_KEYS
                if memo.enabled and len(seen) < MEMO_ENTRIES:
                    seen[(json_key, text)] = keys
            for key in keys:
                origin = wanted[key]
                if key not in left:
                    left[key] = Finding(key[0], origin.value, key[1], origin.alias, first_file=entry.path)
                left[key].count += 1
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


#: Символ → представитель его класса равных под IGNORECASE (w и W, s и ſ): по нему сливаются ветви дерева.
_FOLDED: dict[str, str] = {}


def _fold(ch: str) -> str:
    folded = _FOLDED.get(ch)
    if folded is None:
        # Равенство — то, которое применит сам regex: простое lower и его таблица особых пар.
        folded = next((k for k in set(_FOLDED.values()) if re.fullmatch(re.escape(k), ch, re.IGNORECASE)), ch)
        _FOLDED[ch] = folded
    return folded


#: Предел вложенности групп в свёрнутой альтернации: глубже — `re` не разберёт.
MAX_NESTING = 150


def _nesting(pattern: str) -> int:
    r"""Наибольшая вложенность скобок в регулярке; экранированные `\(` и `\)` не считаются."""
    depth = best = 0
    skip = False
    for ch in pattern:
        if skip:
            skip = False
        elif ch == "\\":
            skip = True
        elif ch == "(":
            depth += 1
            best = max(best, depth)
        elif ch == ")":
            depth -= 1
    return best


def _alternation(strings: Iterable[str]) -> str:
    """Альтернация строк, свёрнутая в дерево по общим началам: `w(?:s(?:1|2))` вместо `ws1|ws2`.

    Под IGNORECASE равна `"|".join(re.escape(s))` по убыванию длины: ветви с разными первыми символами
    (с учётом регистра — равные сливаются) на одном месте друг друга исключают, а внутри ветви конец
    строки — последний вариант, так что, как и там, побеждает самая длинная строка, у которой прошла
    граница. Плоская альтернация перебирает на каждой позиции все строки (на 15 тыс. хостов — около
    0,4 мс на кусок), дерево — только ветвь по первому символу."""
    strings_list = list(strings)
    root: dict[str, dict[str, Any]] = {}
    for string in strings_list:
        node = root
        for ch in string:
            node = node.setdefault(_fold(ch), {})
        node[""] = {}  # конец строки

    # Без рекурсии: рекурсивный обход уходил на глубину в длину строки и на включённом значении
    # длиннее ~1000 символов (длинный секрет из выгрузки) падал с RecursionError. Цепочки без
    # ветвлений склеиваются в один литерал, поэтому вложенность групп равна числу развилок, а не
    # длине строки — иначе и разбор регулярки упёрся бы в свой предел на длинных строках.
    def chain(node: dict[str, dict[str, Any]]) -> tuple[str, dict[str, dict[str, Any]]]:
        run = ""
        while "" not in node and len(node) == 1:
            ch, node = next(iter(node.items()))
            run += re.escape(ch)
        return run, node

    # Пост-обход: (узел, готовые ветви); узел рендерится, когда все его дети собраны.
    out: dict[int, str] = {}
    stack: list[tuple[dict[str, dict[str, Any]], str, bool]] = [(root, "", False)]
    while stack:
        node, prefix, ready = stack.pop()
        if not ready:
            stack.append((node, prefix, True))
            for ch, child in node.items():
                if ch:
                    run, tail = chain(child)
                    stack.append((tail, re.escape(ch) + run, False))
            continue
        branches = [prefix_c + out.pop(id(tail_c)) for prefix_c, tail_c in
                    ((re.escape(ch) + chain(child)[0], chain(child)[1]) for ch, child in node.items() if ch)]
        if not branches:
            out[id(node)] = ""
        elif "" not in node and len(branches) == 1:
            out[id(node)] = branches[0]
        else:
            out[id(node)] = f"(?:{'|'.join(branches)})" + ("?" if "" in node else "")
    pattern = out[id(root)]
    # Вырожденный набор, где строки — префиксы друг друга (`a`, `aa`, `aaa`, …), даёт вложенность групп
    # в длину цепочки, и уже разбор регулярки в `re` упирается в предел рекурсии. Таких наборов в
    # настоящих данных не бывает, но ради закрытости verify лучше плоская альтернация, чем падение.
    if _nesting(pattern) > MAX_NESTING:
        return "|".join(re.escape(s) for s in sorted(set(strings_list), key=len, reverse=True))
    return pattern


def _own_aliases(wanted: dict[Key, Finding], shorts: dict[Key, Key]) -> list[re.Pattern[str]]:
    """Всё, что apply пишет сам: псевдонимы включённых находок (составные — из них же) и метки секретов.
    Псевдоним, совпавший с настоящим значением, не в счёт: иначе он спрятал бы настоящий остаток.

    Границы — общие на всю альтернацию, а не у каждой альтернативы: так regex ищет по общим префиксам
    (на 2000 псевдонимах — десятки секунд на мегабайт против сотых)."""
    reals = {s.casefold() for f in wanted.values() for s in _spellings(f)} | {short for _, short in shorts}
    own = [f for f in wanted.values() if f.alias.casefold() not in reals]
    patterns = []
    # Слово меняется и внутри других слов (password → password-0001), его псевдоним — тоже без границ.
    for words, before, after in ((False, EDGE_BEFORE, EDGE_AFTER), (True, "", "")):
        aliases = {f.alias for f in own if (f.kind == "word") == words}
        if aliases:
            patterns.append(re.compile(f"{before}{_alternation(aliases)}{after}", re.IGNORECASE))
    return patterns


def _spellings(finding: Finding) -> tuple[str, str]:
    """Как включённое значение может встретиться дословно: как найдено и по ключу."""
    return finding.value, finding.value_key


def _literal(wanted: dict[Key, Finding], shorts: dict[Key, Key]) -> Lookup | None:
    """Все включённые значения дословно, без учёта регистра: детектор мог не узнать значение вне
    его привычного окружения (голая учётка без словаря, имя хоста внутри имени файла). Короткие имена
    хостов с точкой (`shorts`) — после собственных написаний: своё значение старше производного."""
    keys: dict[str, Key] = {}
    for key, finding in wanted.items():
        for spelling in _spellings(finding):
            keys.setdefault(spelling.casefold(), key)
    for (_, short), key in shorts.items():
        keys.setdefault(short, key)
    if not keys:
        return None
    return re.compile(f"{EDGE_BEFORE}{_alternation(keys)}{EDGE_AFTER}", re.IGNORECASE), keys


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
