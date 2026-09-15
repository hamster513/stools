from kbaudit.analyzers.hardcode import analyze_hardcode, classify, scan_comparisons
from kbaudit.models import Comparison, KbObject, ObjectType, Polarity


def comparisons(text: str) -> dict[tuple[str, str], Comparison]:
    return {(c.field, c.value): c for c in scan_comparisons(text)}


def test_equality_is_assertion() -> None:
    got = comparisons('event_src.host == "srv01"')
    assert got[("event_src.host", "srv01")].polarity == Polarity.ASSERTION


def test_inequality_is_negation() -> None:
    got = comparisons('event_src.host != "srv01"')
    assert got[("event_src.host", "srv01")].polarity == Polarity.NEGATION


def test_not_in_list_is_negation_and_carries_count() -> None:
    got = comparisons('not in_list(["a1", "b2", "c3"], src.host)')
    item = got[("src.host", "a1")]
    assert item.polarity == Polarity.NEGATION
    assert item.count == 3


def test_plain_in_list_is_assertion() -> None:
    got = comparisons('in_list(["a1", "b2", "c3"], src.host)')
    assert got[("src.host", "a1")].polarity == Polarity.ASSERTION


def test_lower_wrapper_does_not_hide_the_field() -> None:
    got = comparisons('lower(subject.account.name) == "ivanov"')
    assert ("subject.account.name", "ivanov") in got


def test_reversed_comparison_is_found() -> None:
    got = comparisons('"srv01" == event_src.host')
    assert ("event_src.host", "srv01") in got


def cmp(field: str, value: str, count: int = 1, negation: bool = False) -> Comparison:
    return Comparison(
        field=field,
        value=value,
        count=count,
        polarity=Polarity.NEGATION if negation else Polarity.ASSERTION,
    )


def test_builtin_account_never_becomes_a_finding() -> None:
    assert classify(cmp("subject.account.name", "SYSTEM"), in_table=True) is None


def test_class_1_wins_over_everything() -> None:
    assert classify(cmp("src.ip", "10.0.0.1"), in_table=True) == 1


def test_class_2_for_addresses() -> None:
    assert classify(cmp("src.ip", "10.0.0.1"), in_table=False) == 2
    assert classify(cmp("src.subnet", "10.0.0.0/8"), in_table=False) == 2
    assert classify(cmp("dst.fqdn", "dc01.corp.internal"), in_table=False) == 2


def test_class_3_needs_negation_and_three_values() -> None:
    assert classify(cmp("src.host", "srv01", count=3, negation=True), in_table=False) == 3
    assert classify(cmp("src.host", "srv01", count=3), in_table=False) == 5
    assert classify(cmp("src.host", "srv01", count=2, negation=True), in_table=False) == 5


def test_class_4_for_domain_sid() -> None:
    got = classify(cmp("subject.account.id", "S-1-5-21-1234-5678-9012-500"), in_table=False)
    assert got == 4


def test_class_5_for_single_literal() -> None:
    assert classify(cmp("event_src.host", "srv01"), in_table=False) == 5


def test_technical_field_is_not_a_finding() -> None:
    assert classify(cmp("object.process.name", "cmd.exe"), in_table=False) is None
    assert classify(cmp("msgid", "4688"), in_table=False) is None


def test_empty_value_is_not_a_finding() -> None:
    assert classify(cmp("event_src.host", "   "), in_table=False) is None


def test_address_in_technical_field_still_counts() -> None:
    assert classify(cmp("object.name", "10.0.0.1"), in_table=False) == 2


def test_repeated_pair_in_one_body_counts_once() -> None:
    body = KbObject(
        uuid="u1",
        object_type=ObjectType.CORRELATION,
        name="R1",
        body_text='src.ip == "10.0.0.1" and src.ip == "10.0.0.1"',
        body_ext=".co",
    )
    assert len(analyze_hardcode([body], set())) == 1


def test_excerpt_surrounds_the_value() -> None:
    body = KbObject(
        uuid="u1",
        object_type=ObjectType.CORRELATION,
        name="R1",
        body_text='filter { src.ip == "10.0.0.1" }',
        body_ext=".co",
    )
    finding = analyze_hardcode([body], set())[0]
    assert finding.body_excerpt is not None
    assert "10.0.0.1" in finding.body_excerpt


def test_field_without_dot_is_captured_by_the_scanner() -> None:
    """datafield1/datafield2 из ENV_FIELDS пишутся без точки — сканер обязан
    их видеть, иначе поправка задачи 10 не имеет эффекта (regression)."""
    got = comparisons('datafield1 == "incident"')
    assert ("datafield1", "incident") in got


def test_datafield_without_dot_becomes_a_finding() -> None:
    assert classify(cmp("datafield1", "incident"), in_table=False) == 5
    assert classify(cmp("datafield2", "SYSDBA"), in_table=False) == 5


def test_bare_technical_identifier_is_still_not_a_finding() -> None:
    """Захват поля без точки не должен превращать любой bare-идентификатор
    слева от == в находку — отсев по-прежнему делает classify()."""
    got = comparisons('action == "login"')
    assert ("action", "login") in got
    assert classify(cmp("action", "login"), in_table=False) is None


def test_arbitrary_function_wrapper_is_not_mistaken_for_a_comparison() -> None:
    """Раньше `\\)?` после поля была необязательной сама по себе, не привязана
    к тому, сработала ли обёртка функции — совпадало и на постороннем вызове
    произвольной функции. Условная группа `(?(1)\\))` требует закрывающую
    скобку строго тогда, когда сработала одна из разрешённых обёрток."""
    got = comparisons('nonesuch(subject.account.name) == "ivanov"')
    assert ("subject.account.name", "ivanov") not in got


def test_artifact_without_opening_paren_is_not_a_comparison() -> None:
    got = comparisons('x, subject.account.name) == "ivanov"')
    assert ("subject.account.name", "ivanov") not in got
