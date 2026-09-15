"""Разбор локализации правила.

Главное здесь — что заголовок и шаблон сообщения не путаются местами.
Раньше брался первый текст файла, и порядок узлов молча решал, что
считать заголовком.
"""
from kbaudit.parsers.i18n import parse_localization

XML = """<?xml version="1.0" encoding="utf-8"?>
<Localization locale="ru">
  <Description>Обнаружены паттерны Impacket type_id=JC-HC-002-029</Description>
  <EventDescriptions>
    <EventDescription id="a1">На узле {event_src.host} запуск psexec.py</EventDescription>
    <EventDescription id="a2">На узле {event_src.host} запуск wmiexec.py</EventDescription>
    <EventDescription id="a3">   </EventDescription>
  </EventDescriptions>
</Localization>
"""

#: Тот же файл с обратным порядком узлов. Встречается ли такой в выгрузках,
#: неизвестно — но разбор не должен от этого зависеть.
REVERSED = """<?xml version="1.0" encoding="utf-8"?>
<Localization locale="ru">
  <EventDescriptions>
    <EventDescription id="a1">Шаблон сообщения</EventDescription>
  </EventDescriptions>
  <Description>Заголовок правила</Description>
</Localization>
"""


def test_title_and_message_templates_are_separated() -> None:
    loc = parse_localization(XML.encode())
    assert loc.title == "Обнаружены паттерны Impacket type_id=JC-HC-002-029"
    assert loc.descriptions == [
        "На узле {event_src.host} запуск psexec.py",
        "На узле {event_src.host} запуск wmiexec.py",
    ], "пустой шаблон отбрасывается, остальные сохраняют порядок"


def test_order_of_nodes_does_not_decide_what_is_the_title() -> None:
    """Разбор идёт по именам узлов: полагаться на порядок — значит однажды
    молча выдать шаблон сообщения за заголовок правила."""
    loc = parse_localization(REVERSED.encode())
    assert loc.title == "Заголовок правила"
    assert loc.descriptions == ["Шаблон сообщения"]


def test_missing_message_templates_are_not_an_error() -> None:
    """Одиннадцать правил эталонной выгрузки описания не имеют вовсе."""
    raw = b'<Localization><Description>\xd0\xa2\xd0\xbe\xd0\xbb\xd1\x8c\xd0\xba\xd0\xbe</Description></Localization>'
    loc = parse_localization(raw)
    assert loc.title == "Только"
    assert loc.descriptions == []


def test_broken_xml_yields_a_title_and_no_guesses() -> None:
    """На битом файле заголовком считается первый текст, а описаний не
    берётся вовсе: угадывать, какой текст чем является, здесь уже нельзя."""
    loc = parse_localization(b"<Localization><a>\xd0\xbf\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82</a>")
    assert loc.title == "привет"
    assert loc.descriptions == []


def test_empty_localization_gives_nothing() -> None:
    loc = parse_localization(b"<Localization></Localization>")
    assert loc.title is None
    assert loc.descriptions == []
