import json
import zipfile
from collections.abc import Callable
from pathlib import Path

from kbaudit.parsers.rule_body import body_hash, parse_rule_body
from kbaudit.parsers.taxonomy import load_taxonomy

TAXONOMY = {
    "src.ip",
    "dst.ip",
    "object.process.name",
    "subject.name",
    "event_src.host",
    "msgid",
}

BODY = """
event Start:
    key:
        event_src.host
    filter {
        msgid == "4688"
        and in_list(["4697", "4698"], msgid)
        and object.process.name == "cmd.exe"
        and filter::NotFromCorrelator()
    }

query TableQuery = select("host") from DEMO_Critical_Hosts_by_Rule

rule Impacket: Start
    on Start {
        insert_into DEMO_Bruteforce_entities
    }
"""


def test_extracts_events_and_msgids() -> None:
    body = parse_rule_body(BODY, TAXONOMY)
    assert body.events == ["Start"]
    assert body.msgids == ["4688", "4697", "4698"]


def test_extracts_taxonomy_fields_only_for_known_roots() -> None:
    body = parse_rule_body(BODY, TAXONOMY)
    assert "event_src.host" in body.taxonomy_fields
    assert "object.process.name" in body.taxonomy_fields
    assert not any(f.startswith("unknown") for f in body.taxonomy_fields)


def test_extracts_filter_and_table_references() -> None:
    body = parse_rule_body(BODY, TAXONOMY)
    assert body.filter_refs == ["NotFromCorrelator"]
    assert body.table_reads == ["DEMO_Critical_Hosts_by_Rule"]
    assert body.table_writes == ["DEMO_Bruteforce_entities"]


def test_string_null_is_not_a_dependency() -> None:
    body = parse_rule_body('correlation_name == "null"', TAXONOMY)
    assert body.corr_refs == []


def test_real_dependency_is_collected() -> None:
    body = parse_rule_body('correlation_name == "DEMO_Parent_Rule"', TAXONOMY)
    assert body.corr_refs == ["DEMO_Parent_Rule"]


def test_wrapped_correlation_name_equality_is_collected() -> None:
    """lower(correlation_name) == "..." — реальный случай из выгрузки
    (DEMO_MNA_005_004_Possible_Coerce_Authentication_attack)."""
    body = parse_rule_body('lower(correlation_name) == "parent_rule"', TAXONOMY)
    assert body.corr_refs == ["parent_rule"]


def test_wrapped_correlation_name_in_list_is_collected() -> None:
    body = parse_rule_body(
        'in_list(["parent_a", "parent_b"], lower(correlation_name))', TAXONOMY
    )
    assert body.corr_refs == ["parent_a", "parent_b"]


def test_wrapped_string_null_is_still_not_a_dependency() -> None:
    body = parse_rule_body('lower(correlation_name) == "null"', TAXONOMY)
    assert body.corr_refs == []


def test_body_hash_is_stable_and_differs_on_change() -> None:
    assert body_hash("abc") == body_hash("abc")
    assert body_hash("abc") != body_hash("abd")


def test_arbitrary_function_wrapper_is_not_mistaken_for_correlation_name() -> None:
    """Раньше `\\)?` не была привязана к тому, сработала ли сама обёртка —
    из-за этого регэксп мог совпасть на постороннем вызове произвольной
    функции. Явная альтернатива matched-parens такое не пропускает."""
    body = parse_rule_body('какая_угодно(correlation_name) == "X"', TAXONOMY)
    assert body.corr_refs == []


def test_artifact_without_opening_paren_is_not_a_dependency() -> None:
    """И не совпадает на артефакте вида "x, correlation_name)" без открывающей
    скобки вовсе."""
    body = parse_rule_body('x, correlation_name) == "X"', TAXONOMY)
    assert body.corr_refs == []


def test_in_list_field_named_correlation_name_extra_is_not_collected() -> None:
    """Поле, чьё имя лишь НАЧИНАЕТСЯ с correlation_name (например
    correlation_name_extra), — не ссылка на родителя. Регрессия, найденная
    ревью: при переходе на явную альтернативу голая ветка потеряла границу
    слова, и in_list([...], correlation_name_extra) молча попадал бы
    в corr_refs, как будто это ссылка на родителя."""
    body = parse_rule_body(
        'in_list(["parent_a", "parent_b"], correlation_name)', TAXONOMY
    )
    assert body.corr_refs == ["parent_a", "parent_b"]

    body_extra = parse_rule_body(
        'in_list(["parent_a", "parent_b"], correlation_name_extra)', TAXONOMY
    )
    assert body_extra.corr_refs == []


def test_equality_field_named_correlation_name_extra_is_not_collected() -> None:
    """Тот же случай для сравнения через ==: он и раньше не ловился —
    соседний "==" уже ограничивал голую ветку справа, — но покрываем явно,
    чтобы граница слова была закреплена тестом, а не только рассуждением."""
    body = parse_rule_body('correlation_name == "parent_rule"', TAXONOMY)
    assert body.corr_refs == ["parent_rule"]

    body_extra = parse_rule_body('correlation_name_extra == "parent_rule"', TAXONOMY)
    assert body_extra.corr_refs == []


def test_field_matching_uses_full_taxonomy_name_not_root(
    synthetic_zip: Callable[..., Path],
) -> None:
    """Регрессия на находку ревью: load_taxonomy() отдаёт ПОЛНЫЕ ключи
    taxonomy.json ("src.ip", а не "src") — в настоящем файле корня "src"
    как отдельного ключа нет вовсе. Раньше parse_rule_body сравнивал
    t.split(".")[0] с этим множеством полных имён, и любое поле под
    src/dst/event_src/... отбрасывалось молча, потому что его корень
    никогда не совпадал ни с одним полным ключом.

    Тест собирает таксономию тем же путём, что и продовый код (через
    load_taxonomy из архива с настоящей формой ключей), а не через
    фикстуру вида {"src": {}}, которая маскировала расхождение контрактов.
    """
    zip_path = synthetic_zip({
        "taxonomy.json": json.dumps({"src.ip": {}, "event_src.host": {}}),
    })
    with zipfile.ZipFile(zip_path) as zf:
        taxonomy = load_taxonomy(zf)

    assert taxonomy.fields == {"src.ip", "event_src.host"}

    body = parse_rule_body('src.ip == "10.0.0.1"', taxonomy.fields)
    assert "src.ip" in body.taxonomy_fields
