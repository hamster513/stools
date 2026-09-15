import pytest

from kbaudit.analyzers.fields import (
    ENV_FIELDS,
    TECH_FIELDS,
    FieldPolicy,
    is_builtin_account,
    is_environment_field,
)
from kbaudit.analyzers.hardcode import analyze_hardcode
from kbaudit.models import KbObject, ObjectType


def test_env_and_tech_do_not_overlap() -> None:
    assert ENV_FIELDS & TECH_FIELDS == frozenset()


@pytest.mark.parametrize(
    "field",
    ["event_src.host", "src.ip", "dst.host", "subject.account.name", "src.fqdn"],
)
def test_environment_fields(field: str) -> None:
    assert is_environment_field(field) is True


@pytest.mark.parametrize(
    "field", ["msgid", "action", "object.process.name", "event_src.vendor", "logon_type"]
)
def test_technical_fields_are_not_environment(field: str) -> None:
    assert is_environment_field(field) is False


def test_unknown_field_is_not_environment() -> None:
    assert is_environment_field("object.some.new.thing") is False


@pytest.mark.parametrize(
    "value",
    [
        "SYSTEM",
        "system",
        "NT AUTHORITY\\SYSTEM",
        "LOCAL SERVICE",
        "NETWORK SERVICE",
        "ANONYMOUS LOGON",
        "HOST01MG45$",
    ],
)
def test_builtin_accounts_are_excluded(value: str) -> None:
    assert is_builtin_account(value) is True


@pytest.mark.parametrize("value", ["ivanov", "10.0.0.1", "svcctl", ""])
def test_ordinary_values_are_not_builtin(value: str) -> None:
    assert is_builtin_account(value) is False


@pytest.mark.parametrize(
    "value",
    [
        "система",
        "СИСТЕМА",
        "локальная служба",
        "сетевая служба",
        "анонимный вход",
        "центр nt",
        "ЦЕНТР NT",
        "nt authority",
        "NT AUTHORITY",
    ],
)
def test_russian_builtin_accounts_are_excluded(value: str) -> None:
    """В реальных правилах (DEMO_AC_026_010_DcShadowAttack) один и тот же
    список встроенных учёток дан вперемешку по-русски и по-английски —
    оба написания должны исключаться одинаково."""
    assert is_builtin_account(value) is True


@pytest.mark.parametrize("value", ["иванов", "администратор", "петров-сидоров"])
def test_ordinary_russian_names_are_not_builtin(value: str) -> None:
    """Граница не расширяется на принципалы, не перечисленные в ТЗ
    (например, iusr/nt service/window manager) — это доменное решение
    владельца проекта, а не эвристика анализатора."""
    assert is_builtin_account(value) is False


def test_policy_without_extras_matches_builtin_behaviour() -> None:
    """Пустая политика не меняет ничего: эталонные числа держатся на ней."""
    policy = FieldPolicy()
    assert policy.is_environment_field("src.ip") is True
    assert policy.is_environment_field("msgid") is False
    assert policy.is_builtin_account("SYSTEM") is True
    assert policy.is_builtin_account("ivanov") is False


def test_profile_can_add_environmental_fields() -> None:
    """Считать ли datafield3 или hostname средовым — вопрос инсталляции.
    Раньше это требовало правки кода и пересчёта эталона."""
    policy = FieldPolicy.from_roles(environmental=["datafield3", "HostName"])
    assert policy.is_environment_field("datafield3") is True
    assert policy.is_environment_field("hostname") is True, "регистр не важен"
    assert policy.is_environment_field("datafield9") is False


def test_profile_can_add_builtin_accounts() -> None:
    """iusr, nt service и прочие принципалы вне перечня ТЗ добавляются
    профилем, а не коммитом в анализатор."""
    policy = FieldPolicy.from_roles(builtin_accounts=["iusr", "Font Driver Host"])
    assert policy.is_builtin_account("IUSR") is True
    assert policy.is_builtin_account("font driver host") is True
    assert policy.is_builtin_account("ivanov") is False


def test_profile_can_demote_a_field_to_technical() -> None:
    """Обратное направление тоже нужно: поле, объявленное средовым
    по умолчанию, в конкретной инсталляции может быть техническим."""
    policy = FieldPolicy.from_roles(technical=["datafield1"])
    assert policy.is_environment_field("datafield1") is False
    assert policy.is_environment_field("src.ip") is True


def test_policy_changes_classification() -> None:
    """Политика должна доходить до классификатора, а не оседать в модели."""
    body = KbObject(
        uuid="u1",
        object_type=ObjectType.CORRELATION,
        name="R1",
        body_text='datafield7 == "srv01"',
        body_ext=".co",
    )
    assert analyze_hardcode([body], set()) == []

    policy = FieldPolicy.from_roles(environmental=["datafield7"])
    findings = analyze_hardcode([body], set(), None, policy)
    assert [f.kind for f in findings] == [5]
