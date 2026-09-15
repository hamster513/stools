"""Тексты локализации правил.

В файле локализации два разных текста, и путать их нельзя. `Description` —
заголовок правила, в него вендоры часто дописывают служебный код вида
`type_id=JC-MNA-005-004`. `EventDescription` — шаблон сообщения, которое
правило выдаёт при срабатывании, и это единственное место в выгрузке, где
словами написано, что именно правило обнаруживает: «перехватил NTLM-хеш
учётной записи компьютера в результате принудительной аутентификации».

На эталонной выгрузке описание есть у 176 правил из 178 и в среднем
конкретнее заголовка. Раньше бралась только первая строка файла, то есть
заголовок, а описание отбрасывалось.

Структурный код правила здесь не извлекается: он строится применением
схемы именования, определённой по данным выгрузки (`kbaudit.naming`),
а не сопоставлением с шаблоном конкретного вендора.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from pydantic import BaseModel, Field

RE_TEXT_NODE = re.compile(r">([^<>]+)<")


class Localization(BaseModel):
    """Разобранная локализация одной локали."""

    title: str | None = None
    #: Шаблоны сообщений правила. Их бывает несколько: правило с
    #: несколькими ветвями выдаёт разные сообщения.
    descriptions: list[str] = Field(default_factory=list)


def parse_localization(raw: bytes) -> Localization:
    """Заголовок и шаблоны сообщений из файла локализации.

    Разбор идёт по именам узлов, а не по порядку текстов: полагаться на
    то, что заголовок идёт первым, — значит сломаться на файле, где
    порядок другой, и молча выдать шаблон сообщения за заголовок.
    """
    text = raw.decode("utf-8-sig", errors="replace")
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        # Битый XML: заголовком считаем первый текст, описаний не берём —
        # угадывать, какой из текстов чем является, здесь уже нельзя.
        texts = [t.strip() for t in RE_TEXT_NODE.findall(text) if t.strip()]
        return Localization(title=texts[0] if texts else None)

    title_node = root.find("Description")
    title = (title_node.text or "").strip() if title_node is not None else None
    descriptions = [
        node.text.strip()
        for node in root.iter("EventDescription")
        if node.text and node.text.strip()
    ]
    return Localization(title=title or None, descriptions=descriptions)
