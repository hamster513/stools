"""Таблица соответствий в базе (спека §2): кандидаты, нумерация, запись, адреса из таблицы подсетей."""
from __future__ import annotations

from ipaddress import IPv4Network
from typing import Any

from api.modules.toolbox.core.scrub.types import Ctx, Finding
from api.modules.toolbox.models import ToolboxAlias
from api.modules.toolbox.services.aliases import DbAliases

KEY = b"k" * 32
CTX = Ctx(
    domains=frozenset(), hosts=frozenset(), users=frozenset(), words={},
    subnets=[(IPv4Network("10.1.2.0/24"), IPv4Network("10.201.2.0/24"))],
)


def aliases(db: Any) -> DbAliases:
    return DbAliases(db, KEY, "tester", None, CTX)


def test_get_propose_commit_round_trip(db_session: Any) -> None:
    a = aliases(db_session)
    assert a.get("host", "host01") is None
    first = a.propose("host", "host01", "host01")
    assert first == "host-0001"
    # Стабилен внутри задания, следующее значение — следующий номер.
    assert a.propose("host", "Host01", "host01") == "host-0001"
    assert a.propose("host", "srv-db01", "srv-db01") == "host-0002"
    assert a.propose("domain", "corp.test", "corp.test") == "dom1.example"
    assert a.propose("domain", "CORP", "corp") == "DOM2"
    a.commit([("host", "host01", "Host01", "host-0001")])
    db_session.commit()
    row = db_session.query(ToolboxAlias).one()
    assert (row.kind, row.real_key, row.real, row.alias, row.created_by) == ("host", "host01", "Host01", "host-0001", "tester")
    # Новое задание видит таблицу: номер продолжается после записанного.
    b = aliases(db_session)
    assert b.get("host", "host01") == "host-0001"
    assert b.propose("host", "msk1", "msk1") == "host-0002"


def test_secrets_are_never_written(db_session: Any) -> None:
    a = aliases(db_session)
    label = a.propose("secret", "Qwerty123!", "Qwerty123!")
    assert label.startswith("<secret-")
    a.commit([("secret", "Qwerty123!", "Qwerty123!", label)])
    db_session.commit()
    assert db_session.query(ToolboxAlias).count() == 0


def test_subnet_table_address_skips_alias_taken_by_another_value(db_session: Any) -> None:
    # По таблице подсетей 10.1.2.15 → 10.201.2.15, но этот псевдоним уже у другого адреса.
    db_session.add(ToolboxAlias(kind="ip4", real_key="10.9.9.9", real="10.9.9.9", alias="10.201.2.15", created_by="x"))
    db_session.commit()
    a = aliases(db_session)
    alias = a.propose("ip4", "10.1.2.15", "10.1.2.15")
    assert alias not in ("10.201.2.15", "10.1.2.15")
    # Внутри задания тоже: второй адрес с тем же кандидатом получает другой.
    assert a.propose("ip4", "10.1.2.16", "10.1.2.16") == "10.201.2.16"
    other = DbAliases(db_session, KEY, "tester", None, CTX)
    other.reserve([("ip4", "10.1.2.16", "10.201.2.16")])
    assert other.propose("ip4", "10.7.7.7", "10.7.7.7") != "10.201.2.16"


def test_finalize_renumbers_proposal_taken_by_another_job(db_session: Any) -> None:
    # Задание A и задание B предложили host-0001 разным хостам; A применилось первым.
    first, second = aliases(db_session), aliases(db_session)
    assert first.propose("host", "host01", "host01") == second.propose("host", "srv-db01", "srv-db01") == "host-0001"
    found = [Finding("host", "host01", "host01", "host-0001")]
    first.finalize(found)
    first.commit([("host", "host01", "host01", "host-0001")])
    db_session.commit()
    later = [Finding("host", "srv-db01", "srv-db01", "host-0001"), Finding("ip4", "10.1.2.15", "10.1.2.15", "10.201.2.15")]
    changed = aliases(db_session).finalize(later)
    assert later[0].alias == "host-0002" and later[1].alias == "10.201.2.15"
    assert changed == [later[0]]
    db_session.rollback()


def test_numbering_ignores_case_of_stored_aliases(db_session: Any) -> None:
    # Обратный перевод регистр не различает: HOST-0003 и host-0003 — один псевдоним.
    db_session.add(ToolboxAlias(kind="host", real_key="msk1", real="MSK1", alias="HOST-0003", created_by="x"))
    db_session.commit()
    assert aliases(db_session).propose("host", "host01", "host01") == "host-0004"
