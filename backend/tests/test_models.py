import pytest
from pydantic import ValidationError

from kbaudit.models import Finding, ObjectType, Polarity, Rule, RuleBody, RuleCode


def test_rule_code_builds_group_key_from_filled_parts() -> None:
    code = RuleCode(author="DEMO", category="HC", group="002", rule_id="029")
    assert code.group_key == "DEMO/HC/002"


def test_rule_code_tolerates_shallow_schemes() -> None:
    """У разных авторов контента схемы разной глубины — все позиции необязательны."""
    assert RuleCode(category="HC", group="002").group_key == "HC/002"
    assert RuleCode().group_key == ""


def test_rule_defaults_to_ok_parse_status() -> None:
    rule = Rule(uuid="u1", name="R1")
    assert rule.parse_status == "ok"
    assert rule.msgids == []


def test_finding_kind_must_be_one_of_five_classes() -> None:
    with pytest.raises(ValidationError):
        Finding(
            object_type=ObjectType.CORRELATION,
            object_uuid="u1",
            object_name="R1",
            kind=6,
            field="src.ip",
            value="10.0.0.1",
            polarity=Polarity.ASSERTION,
        )


def test_rule_body_fields_are_a_subset_of_rule_fields() -> None:
    """`Rule(**parsed_body.model_dump())` в kbaudit/parsers/snapshot.py собирает
    правило из полей RuleBody через распаковку словаря. Pydantic по умолчанию
    молча игнорирует незнакомые kwargs — если у RuleBody появится поле, которого
    нет у Rule, оно пропадёт при сборке снапшота без единой ошибки: ни ruff,
    ни mypy, ни остальные тесты этого не заметят, а данные будут теряться тихо.
    """
    body_fields = set(RuleBody.model_fields)
    rule_fields = set(Rule.model_fields)
    missing = body_fields - rule_fields
    assert not missing, (
        f"поля {sorted(missing)} есть в RuleBody, но отсутствуют в Rule — "
        "при сборке Rule(**parsed_body.model_dump()) в kbaudit/parsers/snapshot.py "
        "они будут молча отброшены pydantic, и разобранные данные потеряются "
        "без единой ошибки"
    )


def test_finding_severity_derives_from_kind() -> None:
    def sev(kind: int) -> str:
        return Finding(
            object_type=ObjectType.CORRELATION,
            object_uuid="u1",
            object_name="R1",
            kind=kind,
            field="src.ip",
            value="x",
            polarity=Polarity.ASSERTION,
        ).severity

    assert [sev(k) for k in (1, 2, 3, 4, 5)] == ["high", "high", "medium", "medium", "low"]
