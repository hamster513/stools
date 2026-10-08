"""Детекторы движка очистки (спека §1): по функции на kind с одним видом
`find_<kind>(text, ctx) -> Iterator[Match]` и `detect` — все вместе без пересечений.

Регулярные выражения адресов и FQDN перенесены из `backend/tools/export_scrub.py`
(скрипт заморожен). detect-secrets вызывается только отсюда.
"""
from __future__ import annotations

import re
import threading
from collections.abc import Callable, Iterator
from functools import cache, lru_cache
from ipaddress import IPv4Address, IPv6Address

from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class
from detect_secrets.core.scan import scan_line
from detect_secrets.plugins.high_entropy_strings import (
    HexHighEntropyString,
    HighEntropyStringsPlugin,
)
from detect_secrets.settings import cache_bust, configure_settings_from_baseline, get_plugins

from api.modules.toolbox.core.scrub.rules import AUTO, SERVICE, without_overlaps
from api.modules.toolbox.core.scrub.types import KINDS, Ctx, Match

IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
# Кандидат в IPv6; что это адрес, решает ipaddress (время 10:00:01 и MAC им не являются).
IPV6 = re.compile(r"(?<![\w:.])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:]|\.\d)", re.IGNORECASE)
MAC = re.compile(r"(?<![\w:-])[0-9a-f]{2}([:-])[0-9a-f]{2}(?:\1[0-9a-f]{2}){4}(?![\w:-])", re.IGNORECASE)
# Только доменные SID (S-1-5-21-…): встроенные S-1-5-18, S-1-5-32-544 одинаковы везде.
SID = re.compile(r"(?<![\w-])S-1-5-21-\d+-\d+-(\d+)(?:-(\d+))?(?![\w-])")
VERSION_KEY = re.compile(r"version|build", re.IGNORECASE)
FQDN = re.compile(r"(@|(?<![\w.@-]))((?:[a-z0-9-]+\.)+[a-z]{2,})(?![\w-])", re.IGNORECASE)
#: Окончания, по которым «имя.окончание» — файл, а не домен.
FILE_EXT = frozenset({
    "exe", "dll", "sys", "log", "txt", "json", "xml", "ps1", "bat", "cmd", "msi", "tmp", "dat", "ini", "cfg", "conf", "zip", "gz",
    "rar", "bak", "csv", "doc", "docx", "xls", "xlsx", "pdf", "py", "js", "vbs", "scr", "lnk", "db", "sql", "html", "htm", "png",
    "jpg", "cab", "inf", "ocx", "drv", "bin", "iso", "img", "key", "pem", "cer", "crt", "yml", "yaml",
})
# Имя из словаря — целое слово из меток: границы — всё, кроме букв и цифр. «-» и «_» тоже границы
# (host01-notes.txt, host01_old), но внутри имени из словаря они есть (srv-db01) — поэтому текст
# режется на цепочки RUN, цепочки — на метки LABEL, и ищутся отрезки из целых меток.
RUN = re.compile(r"[\w-]+(?:\.[\w-]+)*")
LABEL = re.compile(r"[^._-]+")
NAME = r"[\w-]+(?:\.[\w-]+)*"
NETBIOS_USER = re.compile(rf"(?<![\w-])([\w-]+)\\({NAME})")
# В адресе e-mail бывает «+метка» (a.b+tag@…): без «+» нашлась бы только часть после него.
EMAIL = re.compile(r"(?<![\w.+-])([\w+-]+(?:\.[\w+-]+)*)@((?:[a-z0-9-]+\.)+[a-z]{2,})(?![\w-])", re.IGNORECASE)
KEYWORD = re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*[\"']?([^\s\"',;]{4,})")
AUTH = re.compile(r"(?i)authorization:\s*(bearer|basic)\s+(\S+)")
#: Само ключевое слово перед «=»/«:» — не значение, даже если пароль совпал с ним (password: password).
#: Ключ JSON, под которым значение — секрет: ключевое слово — целое имя или последний сегмент через
#: «_»/«-» (db_password, api-key, access_token). Подстрока не годится: password_policy, token_count,
#: secret_question, tokenizer — не пароли, а секрет на всё значение перекрыл бы в нём учётки и адреса.
#: Служебные «__key__»/«__name__» ни с чем не совпадают.
SECRET_KEY = re.compile(r"(?i)(?:^|[\W_])(?:password|passwd|pwd|secret|token|api[_-]?key|authorization)$")
KEYWORD_NAME = re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|authorization)\s*[=:]")
#: Пустышки на месте значения у ключевого слова: в конфигах и логах их больше, чем настоящих паролей.
#: Переменная — только имя заглавными ($DB_PASS): «$ecretW0rd» — уже пароль.
PLACEHOLDER = re.compile(
    r"(?i:null|none|nil|true|false|yes|no|required|empty|redacted|[*x]{3,}|<[\w -]+>|\$\{[^}]*\}|%[\w-]+%)"
    r"|\$[A-Z_][A-Z0-9_]*",
)
#: Строки длиннее — base64-блоки, на них detect-secrets тормозит; ключевые слова ищутся в любой строке.
SECRET_LINE_MAX = 4096
# Голая hex-строка длины MD5/SHA-1/SHA-256 — хеш файла (их полно в выгрузках антивируса), не секрет;
# под ключевым словом (`token: <64 hex>`) она всё равно найдётся через KEYWORD.
FILE_HASH = re.compile(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", re.IGNORECASE)
#: Короче — обрывки (detect-secrets отдаёт группу regex, например «ghp» от токена GitHub).
SECRET_MIN = 4
WHITESPACE = re.compile(r"\s")
RANK = {kind: i for i, kind in enumerate(KINDS)}


def _by_start(matches: list[Match]) -> Iterator[Match]:
    # Сортировка устойчивая: на одном месте первым остаётся то, что детектор выдал раньше.
    yield from sorted(matches, key=lambda m: m.start)


@lru_cache(maxsize=16)
def _depth(names: frozenset[str]) -> int:
    return max((len(LABEL.findall(n)) for n in names), default=0)


def _dictionary(text: str, names: frozenset[str], kind: str) -> Iterator[Match]:
    """Имена из словаря как целые слова, без учёта регистра; на одном месте — самое длинное.

    Не одна regex-альтернатива из тысяч имён (она перебирает их на каждой позиции), а разбор
    текста на цепочки меток и поиск их отрезков в множестве.
    """
    depth = _depth(names)
    if not depth:
        return
    for run in RUN.finditer(text):
        labels = [(run.start() + m.start(), run.start() + m.end()) for m in LABEL.finditer(run.group(0))]
        i = 0
        while i < len(labels):
            for j in range(min(len(labels), i + depth), i, -1):
                start, end = labels[i][0], labels[j - 1][1]
                if text[start:end].lower() in names:
                    yield Match(start, end, kind, text[start:end])
                    i = j
                    break
            else:
                i += 1


def find_ip4(text: str, ctx: Ctx) -> Iterator[Match]:
    # Под ключами version/build в JSON — номера версий, а не адреса; имя ключа JSON («__key__»,
    # files.KEY) адресом не считается, как в скрипте.
    if ctx.json_key == "__key__" or VERSION_KEY.search(ctx.json_key):
        return
    for m in IPV4.finditer(text):
        try:
            ip = IPv4Address(m.group(0))
        except ValueError:
            continue
        if any(ip in net for net in SERVICE):
            continue
        # «12.3.0.0» вне частных сетей и таблицы подсетей — почти всегда номер версии.
        if m.group(0).endswith(".0.0") and not any(ip in net for net, _ in AUTO) and not any(ip in old for old, _ in ctx.subnets):
            continue
        yield Match(m.start(), m.end(), "ip4", m.group(0))


def find_ip6(text: str, ctx: Ctx) -> Iterator[Match]:
    for m in IPV6.finditer(text):
        try:
            ip = IPv6Address(m.group(0))
        except ValueError:
            continue
        if ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            continue
        yield Match(m.start(), m.end(), "ip6", m.group(0))


def find_mac(text: str, ctx: Ctx) -> Iterator[Match]:
    for m in MAC.finditer(text):
        yield Match(m.start(), m.end(), "mac", m.group(0))


def find_sid(text: str, ctx: Ctx) -> Iterator[Match]:
    # Значение — SID домена: у всех учёток домена он общий и меняется на один псевдоним.
    for m in SID.finditer(text):
        rid = m.group(2)
        yield Match(m.start(), m.end(), "sid", text[m.start():m.end(1)], (("rid", rid),) if rid else ())


def find_domains(text: str, ctx: Ctx) -> Iterator[Match]:
    found = list(_dictionary(text, ctx.domains, "domain"))
    for m in FQDN.finditer(text):
        at, name = m.group(1), m.group(2)
        labels = name.split(".")
        # Без «@» нужны три метки «имя.домен.зона»: две — чаще имя файла или поля, чем домен.
        if labels[-1].lower() in FILE_EXT or (not at and len(labels) < 3):
            continue
        suffix = ".".join(labels[-2:])
        if suffix.lower() in ctx.domains:
            continue
        found.append(Match(m.end(2) - len(suffix), m.end(2), "domain", suffix, auto=True))
    yield from _by_start(found)


def find_hosts(text: str, ctx: Ctx) -> Iterator[Match]:
    # Составные первыми: на том же месте FQDN из словаря хостов уступает им при равной длине.
    found: list[Match] = []
    for m in FQDN.finditer(text):
        if m.group(1):  # домен e-mail — не хост
            continue
        name = m.group(2)
        labels = name.split(".")
        # Домен из словаря может стоять не сразу за первой меткой (msk1.sub.corp.test): всё, что
        # левее самого длинного такого окончания, — имя хоста, иначе средняя метка уцелела бы.
        for k in range(1, len(labels)):
            rest = ".".join(labels[k:])
            if rest.lower() in ctx.domains:
                left = name[:len(name) - len(rest) - 1]
                found.append(Match(m.start(2), m.end(2), "host", name, (("host", left), ("domain", rest))))
                break
    found.extend(_dictionary(text, ctx.hosts, "host"))
    yield from _by_start(found)


def find_users(text: str, ctx: Ctx) -> Iterator[Match]:
    found: list[Match] = []
    for m in NETBIOS_USER.finditer(text):
        if m.group(1).lower() in ctx.domains:
            found.append(Match(m.start(), m.end(), "user", m.group(0), (("domain", m.group(1)), ("user", m.group(2)))))
    for m in EMAIL.finditer(text):
        found.append(Match(m.start(), m.end(), "user", m.group(0), (("user", m.group(1)), ("domain", m.group(2)))))
    found.extend(_dictionary(text, ctx.users, "user"))
    yield from _by_start(found)


@lru_cache(maxsize=16)
def _words_re(words: frozenset[str]) -> re.Pattern[str] | None:
    ordered = sorted(words, key=len, reverse=True)
    return re.compile("|".join(re.escape(w) for w in ordered), re.IGNORECASE) if ordered else None


def find_words(text: str, ctx: Ctx) -> Iterator[Match]:
    # Как в скрипте: часть строки без учёта регистра, длинные слова раньше коротких.
    pattern = _words_re(frozenset(w.lower() for w in ctx.words if w))
    if pattern is None:
        return
    for m in pattern.finditer(text):
        yield Match(m.start(), m.end(), "word", m.group(0))


# Настройки detect-secrets — глобальные для процесса, а scan_line сам их трогает (снимает фильтр,
# сбрасывает кеш фильтров). Поэтому плагины настраиваются один раз, лениво, и все вызовы идут
# под одним замком: временный default_settings() на каждый вызов стоил ~4,6 мс и при параллельных
# сканах в потоках один скан восстанавливал настройки посреди другого — тот молча терял плагины.
_DETECT_SECRETS = threading.Lock()


@cache
def _entropy_plugins() -> dict[str, HighEntropyStringsPlugin]:
    """Включает все плагины detect-secrets на весь процесс; вызывать под _DETECT_SECRETS."""
    cache_bust()
    configure_settings_from_baseline(
        {"plugins_used": [{"name": t.__name__} for t in get_mapping_from_secret_type_to_class().values()]},
    )
    return {p.secret_type: p for p in get_plugins() if isinstance(p, HighEntropyStringsPlugin)}


def _scanned(line: str, entropy: dict[str, HighEntropyStringsPlugin]) -> Iterator[str]:
    for secret in scan_line(line):
        value = secret.secret_value
        if not value or len(value) < SECRET_MIN:
            continue
        # scan_line — режим разового поиска: высокоэнтропийные строки он отдаёт без порога, порог — здесь.
        plugin = entropy.get(secret.type)
        if plugin is not None and plugin.calculate_shannon_entropy(value) <= plugin.entropy_limit:
            continue
        if isinstance(plugin, HexHighEntropyString) and FILE_HASH.fullmatch(value):
            continue
        yield value


def _line_secrets(line: str, offset: int, entropy: dict[str, HighEntropyStringsPlugin]) -> Iterator[Match]:
    spans: dict[tuple[int, int], str] = {}  # одно место — одно совпадение
    # Ключевые слова — ровно на своём месте: то же значение в другом месте строки может быть
    # чем угодно (secret=1234 и порт 12345, token: null).
    for pattern in (KEYWORD, AUTH):
        for m in pattern.finditer(line):
            if not PLACEHOLDER.fullmatch(m.group(2)):
                spans[m.span(2)] = m.group(2)
    if len(line) <= SECRET_LINE_MAX:
        for value in dict.fromkeys(_scanned(line, entropy)):
            # Значение detect-secrets — целый токен, а не кусок другого слова или base64. «=» слева —
            # граница (вид KEY=value), справа — нет: это может быть хвост base64.
            for m in re.finditer(rf"(?<![\w+/]){re.escape(value)}(?![\w+/=])", line):
                spans[m.span()] = value
    for (start, end), value in spans.items():
        yield Match(offset + start, offset + end, "secret", value)


def find_secrets(text: str, ctx: Ctx) -> Iterator[Match]:
    # Значение JSON под ключом-паролем: «password:» в куске нет, ключевое слово — сам ключ. У пароля нет
    # пробелов: значение с пробелами или переносами — обычный текст, его смотрят остальные детекторы.
    if (SECRET_KEY.search(ctx.json_key) and len(text) >= SECRET_MIN and not WHITESPACE.search(text)
            and not PLACEHOLDER.fullmatch(text)):
        yield Match(0, len(text), "secret", text)
        return
    found: list[Match] = []
    with _DETECT_SECRETS:
        entropy = _entropy_plugins()
        offset = 0
        for line in text.split("\n"):
            found.extend(_line_secrets(line, offset, entropy))
            offset += len(line) + 1
    yield from _by_start(found)


FINDERS: tuple[Callable[[str, Ctx], Iterator[Match]], ...] = (
    find_secrets, find_words, find_users, find_hosts, find_domains, find_sid, find_ip4, find_ip6, find_mac,
)


def detect(text: str, ctx: Ctx) -> list[Match]:
    """Все совпадения всех детекторов, без вложенных: при пересечении остаётся более приоритетный kind,
    при равном — более длинный. Отсортированы по start."""
    return without_overlaps(
        (m for find in FINDERS for m in find(text, ctx)),
        lambda m: (RANK[m.kind], m.start - m.end, m.start),
    )
