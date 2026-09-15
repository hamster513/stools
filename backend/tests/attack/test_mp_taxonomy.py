"""Роли полей по документации MaxPatrol SIEM.

Каждый случай здесь стоит за конкретным замером: три раза подряд правило,
казавшееся очевидным, давало сотни ложных находок, и ловил это не
здравый смысл, а прогон на настоящей выгрузке.
"""
from kbaudit.analyzers.mp_taxonomy import role_by_documentation as role


def test_account_attributes_belong_to_the_installation() -> None:
    """«Логин учётной записи», «Домен учётной записи», «имя и фамилия» —
    всё это принадлежит конкретной установке."""
    assert role("subject.account.name") == "environmental"
    assert role("object.account.domain") == "environmental"
    assert role("subject.account.fullname") == "environmental"
    assert role("object.account.dn") == "environmental"
    # Вложенные пути тоже: у приложений своя учётная запись.
    assert role("subject.application.account.name") == "environmental"


def test_privileges_and_session_ids_are_technical() -> None:
    """SeDebugPrivilege одинаков всюду, а Logon ID генерирует система."""
    assert role("subject.account.privileges") == "technical"
    assert role("object.account.session_id") == "technical"


def test_process_identity_is_technical() -> None:
    """`cmd.exe`, его хеш и версия одинаковы в любой инсталляции."""
    assert role("object.process.name") == "technical"
    assert role("subject.process.hash.sha256") == "technical"
    assert role("object.process.original_name") == "technical"


def test_source_product_names_are_technical() -> None:
    """Документация прямо пишет: «windows, asa, ios» и «microsoft, cisco»."""
    assert role("event_src.title") == "technical"
    assert role("event_src.vendor") == "technical"


def test_output_fields_of_the_rule_are_technical() -> None:
    """`alert.*` и `incident.*` — то, что правило пишет само,
    а не то, по чему фильтрует."""
    assert role("alert.context") == "technical"
    assert role("incident.description") == "technical"
    assert role("incident.aggregation.key") == "technical"


def test_geography_is_about_the_internet_not_the_installation() -> None:
    assert role("src.geo.country") == "technical"
    assert role("dst.geo.org") == "technical"


def test_generic_object_names_stay_a_question() -> None:
    """Замер: 146 находок из 177 новых пришлись на `object.name`
    со значением `svcctl` — имя канала, по которому отличают запуск через
    диспетчер служб. Это суть детекта, а не среда."""
    assert role("object.name") is None
    assert role("object.id") is None
    assert role("subject.name") is None


def test_storage_names_stay_a_question() -> None:
    """Замер: рядом с `PROD_AVC_FIN20` там лежат `lsarpc`, `netdfs`,
    `efsrpc` — системные именованные каналы. Одно поле несёт и то и другое."""
    assert role("object.storage.name") is None
    assert role("object.storage.id") is None


def test_paths_and_command_lines_stay_a_question() -> None:
    """`C:\\Windows\\System32\\cmd.exe` одинаков везде, а путь
    к самописному приложению — нет, и лежат они в одном поле."""
    assert role("object.process.fullpath") is None
    assert role("object.process.cmdline") is None
    assert role("datafield8") is None
