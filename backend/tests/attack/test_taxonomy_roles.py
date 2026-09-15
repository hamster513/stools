"""Роли полей выводятся из самой таксономии выгрузки.

Догадки по имени поля здесь не место: taxonomy.json описывает каждое поле
машиночитаемо, и это описание вендора, а не наше предположение.
"""
import io
import json
import zipfile

from kbaudit.parsers.taxonomy import load_taxonomy


def zip_with(taxonomy: dict) -> zipfile.ZipFile:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("taxonomy.json", json.dumps(taxonomy))
    return zipfile.ZipFile(buf)


def test_asset_resolution_by_address_means_environmental() -> None:
    """Прямое указание вендора: по этому полю SIEM разрешает актив
    по имени или адресу, то есть значение уникально для инсталляции."""
    t = load_taxonomy(
        zip_with(
            {
                "src.hostname": {
                    "class": "scalar",
                    "type": "String",
                    "asset_resolution": {"key": "hostname", "role": "subject"},
                }
            }
        )
    )
    assert t.field_roles["src.hostname"] == "environmental"


def test_asset_resolution_by_entity_is_not_environmental() -> None:
    """`event_src.title` разрешает актив по сущности, а не по адресу:
    его значение — «windows», одинаковое всюду. Без этой оговорки одно
    поле давало 325 ложных находок из 349 новых."""
    t = load_taxonomy(
        zip_with(
            {
                "event_src.title": {
                    "class": "scalar",
                    "type": "String",
                    "asset_resolution": {"key": "entity", "role": "eventsource"},
                }
            }
        )
    )
    assert t.field_roles["event_src.title"] == "technical"


def test_enumerated_field_is_technical() -> None:
    """Поле с фиксированным перечнем значений — часть языка детекта,
    а не описание инсталляции."""
    t = load_taxonomy(zip_with({"action": {"class": "tag", "enum": {"execute": {}}}}))
    assert t.field_roles["action"] == "technical"


def test_types_decide_where_they_are_unambiguous() -> None:
    t = load_taxonomy(
        zip_with(
            {
                "dst.ip": {"class": "scalar", "type": "IPAddress"},
                "dst.mac": {"class": "scalar", "type": "MACAddress"},
                "count": {"class": "scalar", "type": "Number"},
                "at": {"class": "scalar", "type": "Datetime"},
            }
        )
    )
    assert t.field_roles["dst.ip"] == "environmental"
    assert t.field_roles["dst.mac"] == "environmental"
    assert t.field_roles["count"] == "technical"
    assert t.field_roles["at"] == "technical"


def test_plain_string_stays_a_question_for_the_human() -> None:
    """Про String таксономия ничего не говорит, и догадываться по имени
    не следует: `object.process.fullpath` бывает и системным путём,
    одинаковым везде, и путём к самописному приложению."""
    t = load_taxonomy(
        zip_with({"object.process.fullpath": {"class": "scalar", "type": "String"}})
    )
    assert "object.process.fullpath" not in t.field_roles


def test_auto_filled_field_is_technical() -> None:
    """Поле заполняет система, а не событие: сравнивать его с литералом
    инсталляции незачем."""
    t = load_taxonomy(zip_with({"agent_id": {"class": "scalar", "type": "String", "auto": True}}))
    assert t.field_roles["agent_id"] == "technical"


def test_broken_taxonomy_yields_no_roles_instead_of_guesses() -> None:
    t = load_taxonomy(zip_with({"weird": "не объект", "other": {"class": "scalar"}}))
    assert t.field_roles == {}
