#!/usr/bin/env python3
"""Чистка выгрузок перед передачей: слова меняются по списку, IP-адреса — по таблице подсетей
и автоматически. Запускается там, где лежат настоящие данные; нужна только стандартная
библиотека Python 3.9+.

    python export_scrub.py --init rules.txt            # шаблон правил со свежим ключом
    python export_scrub.py выгрузка.zip -o чисто.zip -r rules.txt
    python export_scrub.py каталог -o каталог-чисто -r rules.txt

Вход — файл или каталог: .json, .json.gz, .zip (в том числе вложенные), .csv, .txt и любой
другой текст. Файлы, которые не читаются как текст, в результат не попадают.

Правила — текстовый файл, строка «что = на что»:

    ключ = <случайная строка>            # делает автозамену адресов повторяемой
    MSK01TR64 = YU01TR64                 # слово: ищется как часть строки, без учёта регистра
    somedomain.internal = newdomain.internal
    10.1.0.0/16 = 10.201.0.0/16          # подсеть: номер хоста внутри подсети сохраняется
    203.0.113.7 = 198.51.100.7           # отдельный адрес

Слова. Длинные правила применяются раньше коротких, результат замены повторно не меняется.
Регистр найденного сохраняется: ВСЁ ЗАГЛАВНЫМИ и всё строчными — так же, иначе как в правиле.
Короткое слово заменится и внутри других слов — выбирайте правила с этим расчётом.

Адреса. Сначала таблица подсетей (самая узкая подходящая). Остальные частные адреса
(10/8, 172.16/12, 192.168/16) меняются автоматически по ключу: сеть остаётся частной,
последний октет сохраняется, адреса одной подсети остаются в одной подсети. Публичные адреса
вне таблицы меняются на случайные из 8.8.0.0/16 (по ключу, разные адреса — в разные). Не
меняются служебные (127/8, 0.0.0.0, маски, 169.254/16, групповые) и похожие на номер версии
«x.y.0.0». В JSON адреса не ищутся в именах ключей и в значениях под ключом с «version» или
«build» — там номера версий; в обычном тексте такой защиты нет: публичный с виду номер версии
будет заменён, защитить его можно правилом «адрес = тот же адрес». Значение адресом
не считается; двоичные адреса KSC (`octets`, 4 байта) меняются тем же правилом. IPv6 и
MAC-адреса не меняются.

Отчёт печатается в конце: сколько раз сработало каждое правило; подсети вне таблицы, заменённые
автоматически (кандидаты в таблицу); имена хостов и
доменов, оставшиеся без изменений (в JSON — по полям с именем хоста, в любом тексте — по виду
«имя.домен.зона»); окончания доменных имён в результате. Отчёт содержит настоящие
значения: вместе с результатом его не передавать. Файл правил и ключ — тоже.

Код возврата: 0 — готово; 1 — ошибка в аргументах или правилах; 2 — в результате остались
слова из правил.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import hashlib
import hmac
import io
import ipaddress
import json
import re
import secrets
import sys
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
#: Частные сети для автозамены: (сеть, сколько старших бит не трогать). Последний октет не меняется.
AUTO = tuple((ipaddress.IPv4Network(n), keep) for n, keep in (("10.0.0.0/8", 8), ("172.16.0.0/12", 12), ("192.168.0.0/16", 16)))
#: Служебные адреса: не меняются и в отчёт не идут.
SERVICE = tuple(ipaddress.IPv4Network(n) for n in ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3"))
VERSION_KEY = re.compile(r"version|build", re.IGNORECASE)
KEY_NAMES = ("ключ", "key")
#: Ключи JSON, под которыми лежит имя хоста или домена (выгрузки KSC, AD, VM, Assets).
HOST_KEY = re.compile(
    r"hostname|host_name|host_dn|wks_dn|dnsname|dnsdomain|windomain|fqdn|netbios|computer|samaccountname|srv_dn|srv_addr|^(host|dns|server)$",
    re.IGNORECASE,
)
#: Словари, ключи которых — имена хостов.
HOSTS_DICT = re.compile(r"^host_|by_host", re.IGNORECASE)
HOST_NAME = re.compile(r"(?=.*[^\W\d_])[\w.-]{2,64}")
GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
FQDN = re.compile(r"(@|(?<![\w.@-]))((?:[a-z0-9-]+\.)+[a-z]{2,})(?![\w-])", re.IGNORECASE)
#: Окончания, по которым «имя.окончание» — файл, а не домен.
FILE_EXT = frozenset({
    "exe", "dll", "sys", "log", "txt", "json", "xml", "ps1", "bat", "cmd", "msi", "tmp", "dat", "ini", "cfg", "conf", "zip", "gz", "rar", "bak", "csv", "doc", "docx", "xls",
    "xlsx", "pdf", "py", "js", "vbs", "scr", "lnk", "db", "sql", "html", "htm", "png", "jpg", "cab", "inf", "ocx", "drv", "bin", "iso", "img", "key", "pem", "cer", "crt", "yml", "yaml",
})
TEMPLATE = """# Правила чистки выгрузок: «что = на что», одна пара на строку. Строки с # — комментарии.
# Этот файл и ключ остаются у вас: по ним замену можно обратить.
ключ = {key}

# Слова (имена хостов, домены, фамилии, названия) — ищутся как часть строки, без учёта регистра:
# MSK01TR64 = YU01TR64
# somedomain.internal = newdomain.internal

# Подсети и отдельные адреса — номер хоста внутри подсети сохраняется:
# 10.1.0.0/16 = 10.201.0.0/16
# 203.0.113.7 = 198.51.100.7
"""


class RulesError(Exception):
    pass


def _network(text: str) -> ipaddress.IPv4Network | None:
    try:
        return ipaddress.IPv4Network(text, strict=False)
    except ValueError:
        return None


def _net24(address: str) -> str:
    return address.rsplit(".", 1)[0] + ".0/24"


class Scrubber:
    def __init__(self, rules_text: str) -> None:
        self.key = b""
        self.words: dict[str, tuple[str, str]] = {}
        self.subnets: list[tuple[ipaddress.IPv4Network, ipaddress.IPv4Network]] = []
        for number, raw in enumerate(rules_text.splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            left, sep, right = (part.strip() for part in line.partition("="))
            if not sep or not left or not right:
                raise RulesError(f"строка {number}: нужна пара «что = на что»")
            if left.lower() in KEY_NAMES:
                self.key = right.encode()
                continue
            old, new = _network(left), _network(right)
            if old is None:
                self.words[left.lower()] = (left, right)
            elif new is None or old.prefixlen != new.prefixlen:
                raise RulesError(f"строка {number}: подсеть меняется на подсеть той же длины")
            else:
                self.subnets.append((old, new))
        if not self.words and not self.subnets and not self.key:
            raise RulesError("в файле правил нет ни одного правила")
        self.random_key = not self.key
        if self.random_key:
            self.key = secrets.token_bytes(16)
        self.subnets.sort(key=lambda pair: -pair[0].prefixlen)
        ordered = sorted(self.words, key=len, reverse=True)
        self.word_re = re.compile("|".join(re.escape(w) for w in ordered), re.IGNORECASE) if ordered else None
        self.targets = [new.lower() for _, new in self.words.values()]
        self.auto_cache: dict[int, int] = {}
        self.public_map: dict[str, str] = {}
        self.public_taken: set[int] = set()
        self.word_hits: Counter[str] = Counter()
        self.subnet_hits: Counter[str] = Counter()
        self.auto_hits = 0
        self.public: Counter[str] = Counter()
        self.auto_nets: Counter[str] = Counter()
        self.hosts_left: Counter[str] = Counter()
        self.domains: Counter[str] = Counter()
        self.files = 0
        self.skipped: list[str] = []
        self.leftovers = 0

    # --- адреса -------------------------------------------------------------------------------
    def _auto(self, value: int, keep: int) -> int:
        if value not in self.auto_cache:
            out = value
            for bit in range(keep, 24):
                flip = hmac.new(self.key, f"{bit}:{value >> (32 - bit)}".encode(), hashlib.sha256).digest()[0] & 1
                out ^= flip << (31 - bit)
            # Адрес, совпавший сам с собой, сдвигается вместе с соседней подсетью.
            self.auto_cache[value] = out ^ (1 << 8) if out == value else out
        return self.auto_cache[value]

    def address(self, text: str) -> str:
        try:
            ip = ipaddress.IPv4Address(text)
        except ValueError:
            return text
        for old, new in self.subnets:
            if ip in old:
                self.subnet_hits[str(old)] += 1
                return str(ipaddress.IPv4Address(int(new.network_address) | (int(ip) & int(old.hostmask))))
        for net, keep in AUTO:
            if ip in net:
                self.auto_hits += 1
                self.auto_nets[_net24(text)] += 1
                return str(ipaddress.IPv4Address(self._auto(int(ip), keep)))
        # «12.0.0.0» вне таблицы — почти всегда номер версии, не меняется.
        if any(ip in net for net in SERVICE) or text.endswith(".0.0"):
            return text
        self.public[text] += 1
        if text not in self.public_map:
            # Случайный по ключу адрес из 8.8.0.0/16; занятый другим адресом — следующий свободный.
            low = int.from_bytes(hmac.new(self.key, text.encode(), hashlib.sha256).digest()[:2], "big")
            while low in self.public_taken and len(self.public_taken) < 65536:
                low = (low + 1) % 65536
            self.public_taken.add(low)
            self.public_map[text] = f"8.8.{low >> 8}.{low & 255}"
        return self.public_map[text]

    # --- текст --------------------------------------------------------------------------------
    def _word(self, match: re.Match[str]) -> str:
        found = match.group(0)
        old, new = self.words[found.lower()]
        self.word_hits[old] += 1
        if found.isupper():
            return new.upper()
        return new.lower() if found.islower() else new

    def text(self, value: str, *, addresses: bool = True) -> str:
        if addresses:
            value = IPV4.sub(lambda m: self.address(m.group(0)), value)
        return self.word_re.sub(self._word, value) if self.word_re else value

    def _walk(self, value: Any, key: str = "") -> Any:
        if isinstance(value, dict):
            inner = value.get("value")
            if key.lower() == "octets" and value.get("type") == "binary" and isinstance(inner, str):
                try:
                    octets = base64.b64decode(inner, validate=True)
                except (binascii.Error, ValueError):
                    octets = b""
                if len(octets) == 4:
                    changed = self.address(".".join(str(b) for b in octets))
                    return {**value, "value": base64.b64encode(bytes(int(p) for p in changed.split("."))).decode()}
            if HOSTS_DICT.search(key):
                for name in value:
                    self._host(name)
            return {self.text(k, addresses=False): self._walk(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [self._walk(v, key) for v in value]
        if isinstance(value, str):
            if HOST_KEY.search(key):
                self._host(value)
            return self.text(value, addresses=not VERSION_KEY.search(key))
        return value

    def _host(self, name: str) -> None:
        """Имя хоста или домена, которое правила не изменят, — в отчёт."""
        if HOST_NAME.fullmatch(name) and not GUID.fullmatch(name) and not IPV4.fullmatch(name) and self.text(name, addresses=False) == name:
            self.hosts_left[name.lower()] += 1

    def _inspect(self, text: str) -> None:
        """Что осталось в готовом тексте: слова из правил и доменные имена — в отчёт."""
        if self.word_re:
            self.leftovers += len(self.word_re.findall(text))
        for at, name in FQDN.findall(text):
            low = name.lower()
            labels = low.split(".")
            if labels[-1] in FILE_EXT or (not at and len(labels) < 3) or any(t in low for t in self.targets):
                continue
            self.domains[".".join(labels[-2:])] += 1
            if not at:
                self.hosts_left[low] += 1

    # --- файлы --------------------------------------------------------------------------------
    def data(self, name: str, raw: bytes) -> bytes | None:
        """Вычищенное содержимое файла либо None — файл не текст и в результат не идёт."""
        low = name.lower()
        if low.endswith(".zip") or raw[:4] == b"PK\x03\x04":
            return self._zip(name, raw)
        if low.endswith(".gz") or raw[:2] == b"\x1f\x8b":
            try:
                inner = self.data(name[:-3] if low.endswith(".gz") else name, gzip.decompress(raw))
            except (OSError, EOFError):
                inner = None
            return None if inner is None else gzip.compress(inner)
        for bom, encoding in ((b"\xef\xbb\xbf", "utf-8-sig"), (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16"), (b"", "utf-8")):
            if raw.startswith(bom):
                break
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            return None
        if "\x00" in text:
            return None
        clean = None
        if text.lstrip()[:1] in ("{", "["):
            try:
                clean = json.dumps(self._walk(json.loads(text)), ensure_ascii=False, separators=(",", ":"))
            except ValueError:
                clean = None
        if clean is None:
            clean = self.text(text)
        self._inspect(clean)
        self.files += 1
        return clean.encode(encoding)

    def _zip(self, name: str, raw: bytes) -> bytes | None:
        out = io.BytesIO()
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as source, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as target:
                for info in source.infolist():
                    if info.is_dir():
                        continue
                    clean = self.data(info.filename, source.read(info))
                    if clean is None:
                        self.skipped.append(f"{name}:{info.filename}")
                    else:
                        target.writestr(self.text(info.filename, addresses=False), clean)
        except (zipfile.BadZipFile, OSError):
            return None
        return out.getvalue()

    def path(self, source: Path, target: Path) -> None:
        if source.is_dir():
            for item in sorted(p for p in source.rglob("*") if p.is_file()):
                relative = Path(*(self.text(part, addresses=False) for part in item.relative_to(source).parts))
                self._file(item, target / relative)
        else:
            self._file(source, target)

    def _file(self, source: Path, target: Path) -> None:
        clean = self.data(source.name, source.read_bytes())
        if clean is None:
            self.skipped.append(str(source))
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(clean)

    # --- отчёт --------------------------------------------------------------------------------
    def report(self) -> str:
        lines = [f"файлов вычищено: {self.files}"]
        if self.skipped:
            lines += ["не текст, в результат не попали:"] + [f"  {name}" for name in self.skipped]
        if self.random_key:
            lines.append("ключ не задан: автозамена адресов при следующем запуске даст другие адреса (строка «ключ = …» в правилах)")
        lines.append("слова:")
        for word, _ in self.words.values():
            hits = self.word_hits[word]
            lines.append(f"  {word} — {hits}" + ("" if hits else " (правило не сработало)"))
        lines.append("адреса по таблице подсетей:")
        for old, _ in self.subnets:
            hits = self.subnet_hits[str(old)]
            lines.append(f"  {old} — {hits}" + ("" if hits else " (правило не сработало)"))
        lines.append(f"адресов заменено автоматически: {self.auto_hits}")
        lines.append(f"публичные адреса, заменены случайными из 8.8.0.0/16 (различных: {len(self.public)}):")
        lines += [f"  {ip} — {count}" for ip, count in self.public.most_common(50)]
        nets = Counter[str]()
        for ip, count in self.public.items():
            nets[_net24(ip)] += count
        lines.append(f"подсети этих публичных адресов — можно задать в таблице (различных: {len(nets)}):")
        lines += [f"  {net} — {count}" for net, count in nets.most_common(50)]
        lines.append(f"частные подсети вне таблицы, заменены автоматически, — можно задать в таблице (различных: {len(self.auto_nets)}):")
        lines += [f"  {net} — {count}" for net, count in self.auto_nets.most_common(50)]
        lines.append(f"имена хостов и доменов без изменений — добавьте правила для своих (различных: {len(self.hosts_left)}):")
        lines += [f"  {name} — {count}" for name, count in self.hosts_left.most_common(200)]
        lines.append(f"доменные имена в результате — проверьте, нет ли среди них ваших (различных окончаний: {len(self.domains)}):")
        lines += [f"  {name} — {count}" for name, count in self.domains.most_common(40)]
        lines.append(f"остатков слов из правил: {self.leftovers}")
        lines.append("Отчёт и файл правил содержат настоящие значения — вместе с результатом их не передавать.")
        return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Чистка выгрузок: замена слов и IP-адресов по правилам.")
    parser.add_argument("source", nargs="?", help="файл или каталог с выгрузками")
    parser.add_argument("-o", "--output", help="куда записать результат (файл или каталог)")
    parser.add_argument("-r", "--rules", help="файл правил")
    parser.add_argument("--init", metavar="ФАЙЛ", help="создать шаблон файла правил со свежим ключом")
    args = parser.parse_args()
    if args.init:
        rules = Path(args.init)
        if rules.exists():
            print(f"{rules}: файл уже есть", file=sys.stderr)
            return 1
        rules.write_text(TEMPLATE.format(key=secrets.token_hex(16)), encoding="utf-8")
        print(f"шаблон правил: {rules}")
        return 0
    if not (args.source and args.output and args.rules):
        parser.error("нужны выгрузка, -o и -r (или --init)")
    source, target = Path(args.source), Path(args.output)
    if not source.exists():
        print(f"{source}: не найдено", file=sys.stderr)
        return 1
    if target.resolve() == source.resolve() or source.resolve() in target.resolve().parents:
        print("результат нельзя писать поверх исходных данных или внутрь них", file=sys.stderr)
        return 1
    try:
        scrubber = Scrubber(Path(args.rules).read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, RulesError) as error:
        print(f"правила: {error}", file=sys.stderr)
        return 1
    scrubber.path(source, target)
    print(scrubber.report())
    return 2 if scrubber.leftovers else 0


if __name__ == "__main__":
    sys.exit(main())
