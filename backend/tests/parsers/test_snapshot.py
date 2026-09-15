import json
from collections.abc import Callable
from pathlib import Path

from kbaudit.models import ParseStatus
from kbaudit.parsers.snapshot import parse_archive

U1 = "000ffb49-bb9e-4ee4-9262-6754b7ee28d2"
U2 = "111ffb49-bb9e-4ee4-9262-6754b7ee28d2"

META = """
ObjectId: LOC-CR-1
Origin: Local
EventDescriptions:
- Criteria: 'correlation_name = "DEMO_HC_002_029_Impacket"'
"""

CO = """
event Start:
    filter { msgid == "4688" and event_src.host == "host31.corp.internal" }
query Q = select("h") from DEMO_Critical_Hosts_by_Rule
"""

#: Настоящая структура файла локализации MaxPatrol SIEM: заголовок правила
#: и отдельно шаблон сообщения, которое правило выдаёт при срабатывании.
I18N = """<?xml version="1.0" encoding="utf-8"?>
<Localization locale="ru">
  <Description>Паттерны Impacket type_id=JC-HC-002-029</Description>
  <EventDescriptions>
    <EventDescription id="a1">На узле {event_src.host} обнаружена попытка запуска psexec.py</EventDescription>
  </EventDescriptions>
</Localization>"""


def build(synthetic_zip: Callable[..., Path]) -> Path:
    return synthetic_zip({
        "taxonomy.json": json.dumps({"msgid": {}, "event_src.host": {}}),
        f"correlation-rules/rules/correlation/{U1}/metainfo.yaml": META,
        f"correlation-rules/rules/correlation/{U1}/DEMO_HC_002_029_Impacket.co": CO,
        f"correlation-rules/rules/correlation/{U1}/i18n/i18n_ru.xml": I18N,
        f"correlation-rules/rules/correlation/{U2}/metainfo.yaml": META,
        f"correlation-rules/rules/correlation/{U2}/Weird.cojs": "// другой синтаксис",
        "correlation_defaults.json": json.dumps({"T": {"rows": [["host31.corp.internal"]]}}),
    })


def test_builds_rules_with_code_and_titles(synthetic_zip: Callable[..., Path]) -> None:
    parsed = parse_archive(build(synthetic_zip))
    by_uuid = {r.uuid: r for r in parsed.rules}
    rule = by_uuid[U1]
    assert rule.name == "DEMO_HC_002_029_Impacket"
    assert rule.title_ru is not None and rule.title_ru.startswith("Паттерны Impacket")
    assert rule.msgids == ["4688"]
    assert rule.body_hash is not None
    assert rule.code is None, (
        "структурный код назначается на этапе анализа по схеме именования, "
        "а не при разборе: разбор не должен знать соглашений автора правил"
    )


def test_rule_is_scoped_only_by_tables_the_caller_names(
    synthetic_zip: Callable[..., Path],
) -> None:
    """Ограничение областью действия — суждение вызывающего, не модели.

    Раньше имя списка было зашито в доменную модель; после ухода вендора
    такое допущение перестало быть верным.
    """
    parsed = parse_archive(build(synthetic_zip))
    rule = {r.uuid: r for r in parsed.rules}[U1]
    assert rule.is_scoped_by(["DEMO_Critical_Hosts_by_Rule"]) is True
    assert rule.is_scoped_by(["SomeOtherList"]) is False
    assert rule.is_scoped_by([]) is False


def test_cojs_is_marked_unsupported(synthetic_zip: Callable[..., Path]) -> None:
    parsed = parse_archive(build(synthetic_zip))
    weird = next(r for r in parsed.rules if r.uuid == U2)
    assert weird.parse_status == ParseStatus.UNSUPPORTED
    assert weird.msgids == [], "ноль msgid здесь означает «не разобрали»"


def test_bodies_and_table_values_are_collected(
    synthetic_zip: Callable[..., Path],
) -> None:
    parsed = parse_archive(build(synthetic_zip))
    assert len(parsed.bodies) == 2
    assert "host31.corp.internal" in parsed.table_values
