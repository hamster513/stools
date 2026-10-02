#!/usr/bin/env python3
"""Скелет выгрузки KSC: какие секции и ключи есть в политиках и какого типа у них значения.

Нужен, чтобы составить словарь настроек («ключ → понятное название») по настоящей структуре
политик, не вынося данные из контура. Сами значения не печатаются: вместо строки — её вид
(путь, маска, хеш, url, текст…), вместо списка — порядок его размера. Ключи словарей, похожие
на данные, а не на имена настроек (пути, GUID, номера, не-латиница), заменяются метками
`<ключ>`, `<guid>`, `<n>`, `<хеш>`.

Что печатается как есть, потому что это названия из продукта, а не данные площадки: коды и
версии продуктов, имена секций и ключей настроек, названия компонентов защиты и продуктов.

Запуск (нужен только Python 3.8+, без библиотек):

    python3 ksc_policy_skeleton.py <выгрузка.json | выгрузка.json.gz | каталог> [-o skeleton.txt]

Из контейнера STools, по всем снапшотам сервера, не копируя скрипт внутрь:

    docker exec -i stools-api-1 python - /data/ksc < ksc_policy_skeleton.py > skeleton.txt

Перед тем как передавать файл дальше, просмотрите его: это обычный текст."""
from __future__ import annotations

import gzip
import json
import re
import sys
from pathlib import Path
from typing import Any

FORMAT = "stools-ksc/1"
MAX_DEPTH = 60
HIDDEN = "<скрыто>"

_GUID = re.compile(r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$")
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_NAME = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_.\-]{0,79}$")
_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")
_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
_VAR = re.compile(r"%[A-Za-z_][A-Za-z0-9_()]*%")
_PATH = re.compile(r"^([A-Za-z]:[\\/]|\\\\|/)")
_BASE64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_LABEL = re.compile(r"^[A-Za-z0-9_.\- ]{1,40}$")


def _is_hash(text: str) -> bool:
    return len(text) in (32, 40, 64) and bool(_HEX.match(text))


def safe_key(key: Any) -> str:
    """Имя настройки остаётся; ключ, похожий на данные, заменяется меткой."""
    text = str(key)
    if text.isdigit():
        return "<n>"
    if _GUID.match(text):
        return "<guid>"
    if _is_hash(text):
        return "<хеш>"
    if _NAME.match(text) and re.search(r"[A-Za-z]", text):
        return text
    return "<ключ>"


def string_kinds(text: str) -> set[str]:
    """Вид строки без её содержания."""
    if text == "":
        return {"пусто"}
    if text == HIDDEN:
        return {"скрыто"}
    if _GUID.match(text):
        return {"guid"}
    if _is_hash(text):
        return {"хеш"}
    if text.isdigit():
        return {"число"}
    if _IP.match(text):
        return {"ip"}
    if _URL.match(text):
        return {"url"}
    kinds = set()
    if "*" in text or "?" in text:
        kinds.add("маска")
    if _VAR.search(text):
        kinds.add("переменная")
    if _PATH.match(text) or "\\" in text:
        kinds.add("путь")
    if kinds:
        return kinds
    if len(text) >= 24 and len(text) % 4 == 0 and _BASE64.match(text):
        return {"base64"}
    return {"текст"}


def _size(n: int) -> str:
    if n == 0:
        return "0"
    if n < 10:
        return "1–9"
    if n < 100:
        return "10–99"
    return "100+"


class Node:
    """Всё, что известно об одном пути: типы значений, вид строк, размеры списка, признак замка."""

    def __init__(self) -> None:
        self.types: set[str] = set()
        self.kinds: set[str] = set()
        self.sizes: set[str] = set()
        self.lock = False

    def lines(self, path: str) -> list[str]:
        lock = ", замок" if self.lock else ""
        out = []
        if self.sizes:
            sizes = "пустой" if self.sizes == {"0"} else "элементов " + " / ".join(sorted(self.sizes, key=["0", "1–9", "10–99", "100+"].index))
            out.append(f"{path} : список, {sizes}{lock}")
            lock = ""
        if self.types:
            kinds = f" ({', '.join(sorted(self.kinds))})" if self.kinds else ""
            out.append(f"{path} : {' | '.join(sorted(self.types))}{kinds}{lock}")
        return out


def _typed(value: Any) -> str | None:
    """Имя типа KSC, если значение — обёртка `{"type": …, "value": …}`."""
    if isinstance(value, dict) and set(value.keys()) == {"type", "value"} and isinstance(value["type"], str):
        return value["type"]
    return None


def walk(value: Any, path: str, lock: bool, nodes: dict[str, Node], depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        nodes.setdefault(path, Node()).types.add(f"<глубже {MAX_DEPTH}>")
        return
    kind = _typed(value)
    if kind == "params":
        walk(value["value"], path, lock, nodes, depth + 1)
        return
    if kind is not None:
        node = nodes.setdefault(path or "<значение>", Node())
        node.types.add(kind if _NAME.match(kind) else "<тип>")
        node.lock = node.lock or lock
        return
    if isinstance(value, dict):
        if "KLPRSS_Val" in value:
            # Контейнер настройки: значение лежит в `KLPRSS_Val`, признак замка — наличие `KLPRSS_Mnd`.
            walk(value["KLPRSS_Val"], path, "KLPRSS_Mnd" in value, nodes, depth + 1)
            return
        for key, child in value.items():
            name = safe_key(key)
            walk(child, f"{path}.{name}" if path else name, lock, nodes, depth + 1)
        return
    if isinstance(value, list):
        item_path = f"{path}[]"
        node = nodes.setdefault(item_path, Node())
        node.sizes.add(_size(len(value)))
        node.lock = node.lock or lock
        for item in value:
            # Замок относится к списку целиком, на элементы не переносится.
            walk(item, item_path, False, nodes, depth + 1)
        return
    node = nodes.setdefault(path or "<значение>", Node())
    node.lock = node.lock or lock
    if value is None:
        node.types.add("null")
    elif isinstance(value, bool):
        node.types.add("bool")
    elif isinstance(value, int):
        node.types.add("int")
    elif isinstance(value, float):
        node.types.add("float")
    else:
        node.types.add("str")
        node.kinds |= string_kinds(str(value))


def _plain(value: Any) -> Any:
    """Снимает обёртки типов, чтобы прочитать поле записи (имя и состояние компонента)."""
    if _typed(value) is not None:
        return _plain(value["value"])
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    return value


def _label(text: Any) -> str:
    return str(text) if _LABEL.match(str(text)) else "<…>"


def load(path: Path) -> dict[str, Any] | None:
    data = path.read_bytes()
    try:
        if data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
        raw = json.loads(data.decode("utf-8-sig"))
    except (OSError, EOFError, ValueError):
        return None
    if not isinstance(raw, dict) or raw.get("format") != FORMAT:
        return None
    return raw


class Skeleton:
    def __init__(self) -> None:
        self.files = 0
        #: продукт → {"policies": число, "sections": {имя: {"seen": число, "nodes": {...}}}, "failed": имена}
        self.products: dict[str, dict[str, Any]] = {}
        #: «продукт версия» → {"fields": имена полей записи, "components": {название: состояния}}
        self.components: dict[str, dict[str, Any]] = {}
        self.product_names: dict[str, set[str]] = {}

    def add(self, export: dict[str, Any]) -> None:
        self.files += 1
        for content in (export.get("policy_contents") or {}).values():
            if isinstance(content, dict):
                self._policy(content)
        for per_product in (export.get("host_components") or {}).values():
            if isinstance(per_product, dict):
                self._host_components(per_product)
        for per_product in (export.get("host_products") or {}).values():
            self._host_products(_plain(per_product))

    def _policy(self, content: dict[str, Any]) -> None:
        title = f"{_label(content.get('product'))} {_label(content.get('version'))}"
        product = self.products.setdefault(title, {"policies": 0, "sections": {}, "failed": set()})
        product["policies"] += 1
        sections = _plain_params(content.get("sections")) or {}
        for name, raw in sections.items():
            section = product["sections"].setdefault(safe_key(name), {"seen": 0, "nodes": {}})
            section["seen"] += 1
            walk(raw, "", False, section["nodes"])
        for error in content.get("errors") or []:
            product["failed"].add(safe_key(str(error).split(":", 1)[0].strip()))

    def _host_components(self, per_product: dict[str, Any]) -> None:
        for key, items in per_product.items():
            title = " ".join(_label(part) for part in str(key).split("/", 1))
            block = self.components.setdefault(title, {"fields": set(), "components": {}})
            for item in _plain(items) or []:
                if not isinstance(item, dict):
                    continue
                block["fields"] |= {safe_key(k) for k in item}
                name = str(item.get("KLHST_PRCST_COMPONENT_DN") or "<без названия>")
                block["components"].setdefault(name, set()).add(item.get("KLHST_PRCST_COMPONENT_STATUS"))

    def _host_products(self, per_product: Any) -> None:
        if not isinstance(per_product, dict):
            return
        for code, versions in per_product.items():
            if not isinstance(versions, dict):
                continue
            for version, info in versions.items():
                display = info.get("DisplayName") if isinstance(info, dict) else None
                self.product_names.setdefault(f"{_label(code)} {_label(version)}", set()).add(str(display or ""))

    def render(self) -> str:
        out = [
            "# Скелет выгрузки KSC (stools-ksc skeleton/1): имена секций и ключей, типы и вид значений.",
            "# Значений настроек здесь нет. Просмотрите файл перед тем, как передавать его дальше.",
            f"файлов выгрузки: {self.files}",
            "",
        ]
        if not self.products:
            out.append("содержимого политик в выгрузке нет (сбор шёл с -SkipPolicyContents или политик защиты нет)")
        for title in sorted(self.products):
            product = self.products[title]
            out.append(f"ПРОДУКТ {title}")
            if product["failed"]:
                out.append(f"  не прочитались секции: {', '.join(sorted(product['failed']))}")
            for name in sorted(product["sections"]):
                section = product["sections"][name]
                partial = "" if section["seen"] == product["policies"] else " (не во всех политиках)"
                out.append(f"  СЕКЦИЯ {name}{partial}")
                nodes: dict[str, Node] = section["nodes"]
                if not nodes:
                    out.append("    <пусто>")
                for path in sorted(nodes):
                    out.extend(f"    {line}" for line in nodes[path].lines(path))
            out.append("")
        if not self.components:
            out.append("компонентов хостов в выгрузке нет (сбор шёл с -SkipProducts)")
        else:
            out.append("КОМПОНЕНТЫ ЗАЩИТЫ НА ХОСТАХ")
            for title in sorted(self.components):
                block = self.components[title]
                out.append(f"  {title}")
                out.append(f"    поля записи: {', '.join(sorted(block['fields']))}")
                for name in sorted(block["components"]):
                    states = ", ".join(str(s) for s in sorted(block["components"][name], key=str))
                    out.append(f"    {name} — состояния {states}")
        if self.product_names:
            out.append("")
            out.append("ПРОДУКТЫ НА ХОСТАХ")
            for title in sorted(self.product_names):
                names = ", ".join(f"«{n}»" for n in sorted(self.product_names[title]) if n)
                out.append(f"  {title}{' — ' + names if names else ''}")
        return "\n".join(out) + "\n"


def _plain_params(value: Any) -> Any:
    """Секции политики приходят словарём, иногда в обёртке params."""
    if _typed(value) == "params":
        return value["value"]
    return value if isinstance(value, dict) else None


def main(argv: list[str]) -> int:
    args = list(argv)
    target: Path | None = None
    if "-o" in args:
        at = args.index("-o")
        if at + 1 >= len(args):
            print("после -o нужен путь к файлу", file=sys.stderr)
            return 2
        target = Path(args[at + 1])
        del args[at:at + 2]
    if len(args) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    source = Path(args[0])
    if not source.exists():
        print(f"нет такого файла или каталога: {source}", file=sys.stderr)
        return 1
    if source.is_dir():
        files = sorted(p for p in source.iterdir() if p.is_file() and (p.name.endswith(".json") or p.name.endswith(".json.gz")))
    else:
        files = [source]
    skeleton = Skeleton()
    for path in files:
        export = load(path)
        if export is None:
            print(f"пропущен: {path.name} (не выгрузка {FORMAT})", file=sys.stderr)
            continue
        skeleton.add(export)
    if skeleton.files == 0:
        print("ни одной выгрузки KSC не найдено", file=sys.stderr)
        return 1
    text = skeleton.render()
    if target is not None:
        target.write_text(text, encoding="utf-8")
        print(f"скелет записан: {target}")
    else:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
