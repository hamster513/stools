"""Детекторы движка очистки (спека §1): каждый находит своё и не трогает служебное."""
from __future__ import annotations

import dataclasses
from collections.abc import Iterable
from itertools import pairwise

from api.modules.toolbox.core.scrub.detectors import (
    detect,
    find_domains,
    find_hosts,
    find_ip4,
    find_ip6,
    find_mac,
    find_secrets,
    find_sid,
    find_users,
    find_words,
)
from api.modules.toolbox.core.scrub.types import KINDS, STORED_KINDS, Ctx, Match, value_key
from tests.toolbox.synthetic import CTX, TEXT


def values(matches: Iterable[Match]) -> list[str]:
    return [m.value for m in matches]


def with_users(*names: str) -> Ctx:
    return dataclasses.replace(CTX, users=frozenset(names))


def test_kinds_order_is_priority() -> None:
    assert KINDS == ("secret", "word", "user", "host", "domain", "sid", "ip4", "ip6", "mac")
    assert "secret" not in STORED_KINDS and len(STORED_KINDS) == len(KINDS) - 1


def test_value_key_normalizes() -> None:
    assert value_key("host", "HOST01") == "host01"
    assert value_key("ip6", "2001:4860:0:0:0:0:0:8888") == "2001:4860::8888"
    assert value_key("mac", "00-1A-2B-3C-4D-5E") == "00:1a:2b:3c:4d:5e"
    assert value_key("sid", "S-1-5-21-111-222-333") == "S-1-5-21-111-222-333"
    assert value_key("ip4", "10.1.2.15") == "10.1.2.15"


def test_ip4_finds_addresses() -> None:
    found = list(find_ip4("from 10.1.2.15 to 203.0.113.7:443", CTX))
    assert values(found) == ["10.1.2.15", "203.0.113.7"]
    assert (found[0].start, found[0].end) == (5, 14)


def test_ip4_skips_service_and_versions() -> None:
    assert list(find_ip4("127.0.0.1 0.0.0.0 255.255.255.0 169.254.1.1 224.0.0.5", CTX)) == []
    assert list(find_ip4("agent version 12.3.0.0", CTX)) == []
    assert list(find_ip4("1.2.3.4.5 and 999.1.1.1", CTX)) == []
    # Частная сеть вида x.y.0.0 — это адрес сети, а не версия.
    assert values(find_ip4("net 10.1.0.0", CTX)) == ["10.1.0.0"]


def test_ip4_skips_values_under_version_keys() -> None:
    for key in ("version", "BuildNumber"):
        ctx = dataclasses.replace(CTX, json_key=key)
        assert list(find_ip4("10.1.2.3", ctx)) == []
    assert values(find_ip4("10.1.2.3", dataclasses.replace(CTX, json_key="ip"))) == ["10.1.2.3"]


def test_ip6_finds_global_addresses() -> None:
    assert values(find_ip6("peer 2001:4860::8888, also 2001:db8:0:0:1:0:0:1", CTX)) == [
        "2001:4860::8888",
        "2001:db8:0:0:1:0:0:1",
    ]


def test_ip6_skips_service_and_lookalikes() -> None:
    text = "fe80::1 ff02::1 ::1 :: at 10:00:01 mac 00:1A:2B:3C:4D:5E std::abc"
    assert list(find_ip6(text, CTX)) == []


def test_mac_finds_both_separators() -> None:
    assert values(find_mac("a 00:1A:2B:3C:4D:5E b 00-1a-2b-3c-4d-5f", CTX)) == [
        "00:1A:2B:3C:4D:5E",
        "00-1a-2b-3c-4d-5f",
    ]


def test_mac_skips_partial_and_mixed() -> None:
    assert list(find_mac("00:1A:2B:3C:4D 00:1A-2B:3C:4D:5E 00:1A:2B:3C:4D:5E:6F", CTX)) == []


def test_sid_keeps_rid_as_part() -> None:
    [found] = find_sid("sid S-1-5-21-111-222-333-500 end", CTX)
    assert found.value == "S-1-5-21-111-222-333"
    assert found.parts == (("rid", "500"),)
    assert (found.start, found.end) == (4, 28)
    [domain] = find_sid("S-1-5-21-111-222-333", CTX)
    assert domain.parts == ()


def test_sid_skips_builtin() -> None:
    assert list(find_sid("S-1-5-18 S-1-5-32-544 xS-1-5-21-1-2-3", CTX)) == []


def test_domains_dictionary_and_auto() -> None:
    found = list(find_domains("dns CORP.TEST, relay mail.example.test", CTX))
    assert [(m.value, m.auto) for m in found] == [("CORP.TEST", False), ("example.test", True)]


def test_domains_skip_files_and_partial_words() -> None:
    assert list(find_domains("report.final.txt corporate corp-x x.corp_y", CTX)) == []
    # Без «@» имя из двух меток — не FQDN хоста, авто-поиск его не берёт.
    assert list(find_domains("example.test", CTX)) == []


def test_hosts_dictionary_and_fqdn_with_confirmed_domain() -> None:
    found = list(find_hosts("HOST01 and msk1.corp.test", CTX))
    plain = [m for m in found if not m.parts]
    composite = [m for m in found if m.parts]
    assert values(plain) == ["HOST01", "msk1"]
    [fqdn] = composite
    assert fqdn.value == "msk1.corp.test"
    assert fqdn.parts == (("host", "msk1"), ("domain", "corp.test"))
    assert (fqdn.start, fqdn.end) == (11, 25)


def test_hosts_respect_word_boundaries_and_unconfirmed_domains() -> None:
    assert list(find_hosts("host011 xhost01 host01-b", CTX)) == []
    assert [m for m in find_hosts("web7.other.org", CTX) if m.parts] == []


def test_users_composite_netbios_and_email() -> None:
    found = list(find_users("CORP\\jdoe and jdoe@corp.test", CTX))
    assert [(m.value, m.parts) for m in found] == [
        ("CORP\\jdoe", (("domain", "CORP"), ("user", "jdoe"))),
        ("jdoe@corp.test", (("user", "jdoe"), ("domain", "corp.test"))),
    ]


def test_users_skip_unknown_netbios_and_bare_names_without_dictionary() -> None:
    assert list(find_users("OTHER\\jdoe C:\\Windows jdoe", CTX)) == []


def test_users_bare_names_from_dictionary() -> None:
    assert values(find_users("login JDoe ok, jdoe2 no", with_users("jdoe"))) == ["JDoe"]


def test_secrets_three_kinds_value_only() -> None:
    text = "password=Qwerty123!\nAuthorization: Basic am9lOnNlY3JldA==\naws AKIAIOSFODNN7EXAMPLE\n"
    found = list(find_secrets(text, CTX))
    assert sorted(set(values(found))) == sorted(["Qwerty123!", "am9lOnNlY3JldA==", "AKIAIOSFODNN7EXAMPLE"])
    for m in found:
        assert text[m.start:m.end] == m.value


def test_secrets_skip_plain_text_and_long_lines() -> None:
    assert list(find_secrets("hello world, logon host01 ok", CTX)) == []
    long_line = "x" * 4100 + " password=Qwerty123!"
    assert list(find_secrets(long_line, CTX)) == []


def test_words_part_of_string_any_case() -> None:
    assert values(find_words("IVANOVA, acmeCorp, Petrov", CTX)) == ["IVANOV", "acme"]


def test_detect_on_synthetic_log() -> None:
    found = detect(TEXT, CTX)
    assert [m.start for m in found] == sorted(m.start for m in found)
    for a, b in pairwise(found):
        assert a.end <= b.start
    by_value = {(m.kind, m.value) for m in found}
    expected = {
        ("host", "host01.corp.test"),
        ("ip4", "10.1.2.15"),
        ("user", "CORP\\jdoe"),
        ("user", "jdoe@corp.test"),
        ("sid", "S-1-5-21-111-222-333"),
        ("ip6", "2001:4860::8888"),
        ("mac", "00:1A:2B:3C:4D:5E"),
        ("secret", "Qwerty123!"),
        ("secret", "am9lOnNlY3JldA=="),
        ("secret", "AKIAIOSFODNN7EXAMPLE"),
        ("word", "Ivanov"),
        ("word", "ACME"),
        ("domain", "example.test"),
    }
    assert by_value == expected
    texts = [TEXT[m.start:m.end] for m in found]
    assert "host01" not in texts  # внутри host011 и внутри FQDN — не отдельное совпадение
    assert not any(t in ("fe80::1", "127.0.0.1", "12.3.0.0") for t in texts)
    [auto] = [m for m in found if m.kind == "domain"]
    assert auto.auto is True


def test_detect_secret_wins_inside_authorization() -> None:
    line = "Authorization: Basic am9lOnNlY3JldA=="
    found = detect(line, CTX)
    assert [(m.kind, m.value) for m in found] == [("secret", "am9lOnNlY3JldA==")]


def test_detect_priority_and_length_on_overlap() -> None:
    # word выше user: фамилия в e-mail меняется словом, домен — отдельным совпадением.
    found = detect("ivanov@corp.test", CTX)
    assert [(m.kind, m.value) for m in found] == [("word", "ivanov"), ("domain", "corp.test")]
    # Один kind: длинное совпадение побеждает короткое внутри него.
    [fqdn] = detect("srv-db01.corp.test", CTX)
    assert fqdn.kind == "host" and fqdn.value == "srv-db01.corp.test"


def test_match_defaults() -> None:
    m = Match(0, 1, "ip4", "x")
    assert m.parts == () and m.auto is False
