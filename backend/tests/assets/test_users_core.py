"""Пользователи как активы: личность учётки (спека §3) и расхождения (§5) — без базы."""
from __future__ import annotations

import datetime as dt

from api.modules.assets.core.users import (
    UserCard,
    UserHostLink,
    UserSeen,
    is_workstation,
    match_user,
    user_discrepancies,
    user_key,
)

NOW = dt.datetime(2026, 10, 20, 12, 0, tzinfo=dt.UTC)
SID = "S-1-5-21-1111111111-2222222222-3333333333-{}"
DOMAIN_MAP = {"CORP": "corp.local"}
AD_DOMAINS = {"corp.local"}


def seen(**kw: object) -> UserSeen:
    base: dict[str, object] = {"source": "ksc", "source_key": "1:ws01:user01", "seen_at": NOW}
    base.update(kw)
    return UserSeen(**base)  # type: ignore[arg-type]


# --- личность ---------------------------------------------------------------

def test_key_has_sid_and_dns_name() -> None:
    s = seen(source="ad", sid=SID.format(1001), sam="user01", domain="corp.local")
    assert user_key(s, DOMAIN_MAP) == (SID.format(1001), "corp.local\\user01")


def test_netbios_domain_goes_to_dns_by_map() -> None:
    s = seen(sam="CORP\\User01")
    assert user_key(s, DOMAIN_MAP) == ("", "corp.local\\user01")


def test_netbios_domain_field_goes_to_dns_by_map() -> None:
    s = seen(sam="user01", domain="CORP")
    assert user_key(s, DOMAIN_MAP) == ("", "corp.local\\user01")


def test_local_account_on_two_hosts_gives_two_keys() -> None:
    a = seen(sam="admin", local=True, host_asset_id=1)
    b = seen(sam="admin", local=True, host_asset_id=2)
    ka, kb = user_key(a, DOMAIN_MAP), user_key(b, DOMAIN_MAP)
    assert ka == ("", "local:1\\admin")
    assert kb == ("", "local:2\\admin")


def test_local_account_sid_is_not_identity() -> None:
    """SID машины повторяется на клонах без sysprep: локальная учётка склеилась бы между хостами."""
    s = seen(sid="S-1-5-21-9-9-9-500", sam="WS01\\Administrator", local=True, host_asset_id=7)
    assert user_key(s, DOMAIN_MAP) == ("", "local:7\\administrator")


def test_group_is_not_a_user() -> None:
    s = seen(sid=SID.format(513), sam="CORP\\Domain Users", group=True)
    assert user_key(s, DOMAIN_MAP) is None


def test_record_without_sid_and_name_is_not_a_user() -> None:
    assert user_key(seen(sid="", sam=""), DOMAIN_MAP) is None


def test_local_without_host_and_sid_is_not_a_user() -> None:
    assert user_key(seen(sam="admin", local=True), DOMAIN_MAP) is None


def test_sid_wins_over_name() -> None:
    key = (SID.format(1001), "corp.local\\user01")
    assert match_user(key, {SID.format(1001): [1]}, {"corp.local\\user01": [(2, "")]}) == 1


def test_name_matches_when_seen_has_no_sid() -> None:
    key = ("", "corp.local\\user01")
    assert match_user(key, {}, {"corp.local\\user01": [(1, SID.format(1001))]}) == 1


def test_name_does_not_match_user_with_other_sid() -> None:
    """Учётку пересоздали с тем же именем: новый SID — другой пользователь."""
    key = (SID.format(1002), "corp.local\\user01")
    assert match_user(key, {}, {"corp.local\\user01": [(1, SID.format(1001))]}) is None
    assert match_user(key, {}, {"corp.local\\user01": [(1, "")]}) == 1


def test_ambiguous_name_gives_none() -> None:
    key = ("", "corp.local\\user01")
    assert match_user(key, {}, {"corp.local\\user01": [(1, ""), (2, "")]}) is None


def test_ambiguous_sid_gives_none() -> None:
    key = (SID.format(1001), "corp.local\\user01")
    assert match_user(key, {SID.format(1001): [1, 2]}, {"corp.local\\user01": [(3, "")]}) is None


def test_no_match() -> None:
    assert match_user(("", "corp.local\\user01"), {}, {}) is None


# --- рабочая станция ---------------------------------------------------------

def test_is_workstation() -> None:
    assert is_workstation("Microsoft Windows 10 Pro") is True
    assert is_workstation("Windows SERVER 2022 Standard") is False
    assert is_workstation("") is None


# --- расхождения ---------------------------------------------------------------

def card(**kw: object) -> UserCard:
    base: dict[str, object] = {"enabled": True, "privileged": False, "local": False,
                               "domain": "corp.local", "in_ad": True}
    base.update(kw)
    return UserCard(**base)  # type: ignore[arg-type]


def link(asset_id: int = 1, *, name: str = "WS01", os: str = "Windows 10 Pro", kind: str = "session",
         active: bool = True, gone: bool = False, users_collected: bool = True) -> UserHostLink:
    return UserHostLink(asset_id=asset_id, name=name, os=os, kind=kind, active=active, gone=gone,
                        users_collected=users_collected)


def codes(user: UserCard, links: list[UserHostLink]) -> list[tuple[str, int | None]]:
    return [(d.code, d.host_asset_id) for d in user_discrepancies(user, links, AD_DOMAINS)]


def test_disabled_session() -> None:
    found = user_discrepancies(card(enabled=False), [link(active=True), link(2, name="WS02", active=False)], AD_DOMAINS)
    assert [(d.code, d.host_asset_id) for d in found] == [("disabled_session", 1), ("disabled_session", 2)]
    assert "WS01" in found[0].text and "в системе" in found[0].text
    assert "WS02" in found[1].text and "заходил" in found[1].text


def test_disabled_without_live_session_is_quiet() -> None:
    assert codes(card(enabled=False), [link(gone=True), link(2, kind="owner", users_collected=False)]) == []
    assert codes(card(enabled=True), [link()]) == []
    # Нет в AD — не «отключена»: enabled неизвестен.
    assert "disabled_session" not in {c for c, _ in codes(card(enabled=None, in_ad=False), [link()])}


def test_not_in_ad() -> None:
    found = user_discrepancies(card(enabled=None, in_ad=False), [link(), link(2, name="WS02")], AD_DOMAINS)
    assert [(d.code, d.host_asset_id) for d in found] == [("not_in_ad", None)]
    assert "corp.local" in found[0].text and "WS01" in found[0].text and "WS02" in found[0].text


def test_not_in_ad_needs_collected_domain_session_and_domain_account() -> None:
    assert codes(card(enabled=None, in_ad=False, domain="other.local"), [link()]) == []
    assert codes(card(enabled=None, in_ad=False, local=True, domain=""), [link()]) == []
    assert codes(card(enabled=None, in_ad=False), [link(gone=True)]) == []
    assert codes(card(), [link()]) == []


def test_privileged_on_workstation() -> None:
    found = user_discrepancies(card(privileged=True), [link(), link(2, name="SRV01", os="Windows Server 2022")],
                               AD_DOMAINS)
    assert [(d.code, d.host_asset_id) for d in found] == [("privileged_on_workstation", 1)]
    assert "WS01" in found[0].text


def test_privileged_on_server_or_unknown_os_is_quiet() -> None:
    assert codes(card(privileged=True), [link(os="Windows Server 2019"), link(2, os="")]) == []
    assert codes(card(privileged=False), [link()]) == []
    assert codes(card(privileged=True), [link(gone=True)]) == []


def test_owner_without_session() -> None:
    found = user_discrepancies(card(), [link(kind="owner"), link(2, name="WS02")], AD_DOMAINS)
    assert [(d.code, d.host_asset_id) for d in found] == [("owner_without_session", 1)]
    assert "WS01" in found[0].text
    # Ушедший сеанс — уже не сеанс.
    assert codes(card(), [link(kind="owner"), link(kind="session", gone=True)]) == [("owner_without_session", 1)]


def test_owner_with_session_or_uncollected_is_quiet() -> None:
    assert codes(card(), [link(kind="owner"), link(kind="session", active=False)]) == []
    # «Не собрано ≠ пусто»: пользователи хоста не собраны — судить не о чем.
    assert codes(card(), [link(kind="owner", users_collected=False)]) == []
    # Владельцем больше не числится — судить не о чем.
    assert codes(card(), [link(kind="owner", gone=True)]) == []


def test_order_follows_codes() -> None:
    user = card(enabled=False, privileged=True)
    found = codes(user, [link(), link(2, name="WS02", kind="owner")])
    assert found == [("disabled_session", 1), ("privileged_on_workstation", 1), ("owner_without_session", 2)]
