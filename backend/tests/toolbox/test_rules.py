"""Правила замены (спека §1, перенос из export_scrub): регистр, кандидаты, нумерация, сборка, замена."""
from __future__ import annotations

import ipaddress
import re

import pytest

from api.modules.toolbox.core.scrub.rules import candidate, compose, keep_case, numbered, replace
from api.modules.toolbox.core.scrub.types import Match
from tests.toolbox.synthetic import CTX

KEY = b"synthetic-key"


def free(_: str) -> bool:
    return False


@pytest.mark.parametrize(
    ("found", "alias", "expected"),
    [("HOST01", "host-0001", "HOST-0001"), ("host01", "Host-0001", "host-0001"), ("Host01", "host-0001", "host-0001")],
)
def test_keep_case(found: str, alias: str, expected: str) -> None:
    assert keep_case(found, alias) == expected


def test_ip4_by_subnet_table_keeps_host_number() -> None:
    assert candidate("ip4", "10.1.2.15", KEY, free, CTX) == "10.201.2.15"


def test_ip4_private_auto_keeps_zone_last_octet_and_subnet() -> None:
    a = candidate("ip4", "192.168.1.10", KEY, free, CTX)
    b = candidate("ip4", "192.168.1.77", KEY, free, CTX)
    assert ipaddress.IPv4Address(a) in ipaddress.IPv4Network("192.168.0.0/16")
    assert a.endswith(".10") and b.endswith(".77")
    assert a != "192.168.1.10"
    assert a.rsplit(".", 1)[0] == b.rsplit(".", 1)[0]
    assert candidate("ip4", "192.168.1.10", KEY, free, CTX) == a


def test_ip4_public_goes_to_8_8_by_key() -> None:
    a = candidate("ip4", "203.0.113.7", KEY, free, CTX)
    assert re.fullmatch(r"8\.8\.\d{1,3}\.\d{1,3}", a)
    assert candidate("ip4", "203.0.113.7", KEY, free, CTX) == a
    assert candidate("ip4", "203.0.113.7", b"other-key", free, CTX) != a


@pytest.mark.parametrize("kind_key", [("ip4", "203.0.113.7"), ("ip4", "192.168.1.10"), ("ip6", "2001:4860::8888"),
                                      ("mac", "00:1a:2b:3c:4d:5e"), ("sid", "S-1-5-21-111-222-333")])
def test_taken_candidate_is_replaced_by_another(kind_key: tuple[str, str]) -> None:
    kind, key = kind_key
    first = candidate(kind, key, KEY, free, CTX)
    second = candidate(kind, key, KEY, lambda alias: alias == first, CTX)
    assert second != first


def test_ip6_mac_sid_secret_shapes() -> None:
    ip6 = candidate("ip6", "2001:4860::8888", KEY, free, CTX)
    assert ipaddress.IPv6Address(ip6) in ipaddress.IPv6Network("2001:db8::/32")
    mac = candidate("mac", "00:1a:2b:3c:4d:5e", KEY, free, CTX)
    assert re.fullmatch(r"02(:[0-9a-f]{2}){5}", mac)
    sid = candidate("sid", "S-1-5-21-111-222-333", KEY, free, CTX)
    assert re.fullmatch(r"S-1-5-21-\d+-\d+-\d+", sid) and sid != "S-1-5-21-111-222-333"
    secret = candidate("secret", "Qwerty123!", KEY, free, CTX)
    assert re.fullmatch(r"<secret-[0-9a-f]{8}>", secret)
    assert candidate("secret", "Qwerty123!", b"other-key", free, CTX) == secret


def test_numbered_kinds_are_not_candidates() -> None:
    with pytest.raises(ValueError):
        candidate("host", "host01", KEY, free, CTX)


def test_numbered_forms() -> None:
    assert numbered("host", 1) == "host-0001"
    assert numbered("user", 12) == "user-0012"
    assert numbered("word", 3) == "word-0003"
    assert numbered("domain", 1) == "dom1.example"
    assert numbered("domain", 2, key="corp") == "DOM2"
    assert numbered("domain", 2, key="corp.test") == "dom2.example"


ALIASES = {
    ("host", "msk1"): "host-0001",
    ("domain", "corp.test"): "dom1.example",
    ("domain", "corp"): "DOM1",
    ("user", "jdoe"): "user-0001",
    ("sid", "S-1-5-21-111-222-333"): "S-1-5-21-7-8-9",
    ("ip4", "10.1.2.15"): "10.201.2.15",
}


def alias_of(kind: str, value: str) -> str:
    return ALIASES[(kind, value.lower() if kind != "sid" else value)]


def test_compose_composites() -> None:
    host = Match(0, 14, "host", "msk1.corp.test", (("host", "msk1"), ("domain", "corp.test")))
    mail = Match(0, 14, "user", "jdoe@corp.test", (("user", "jdoe"), ("domain", "corp.test")))
    netbios = Match(0, 9, "user", "CORP\\jdoe", (("domain", "CORP"), ("user", "jdoe")))
    sid = Match(0, 24, "sid", "S-1-5-21-111-222-333", (("rid", "500"),))
    plain = Match(0, 9, "ip4", "10.1.2.15")
    assert compose(host, alias_of) == "host-0001.dom1.example"
    assert compose(mail, alias_of) == "user-0001@dom1.example"
    assert compose(netbios, alias_of) == "DOM1\\user-0001"
    assert compose(sid, alias_of) == "S-1-5-21-7-8-9-500"
    assert compose(plain, alias_of) == "10.201.2.15"


def test_replace_single_pass_keeps_case_and_longer_first() -> None:
    text = "HOST msk1.corp.test, msk1"
    matches = [
        Match(5, 9, "host", "msk1"),
        Match(5, 19, "host", "msk1.corp.test", (("host", "msk1"), ("domain", "corp.test"))),
        Match(21, 25, "host", "msk1"),
    ]
    # Псевдоним сам содержит найденное значение: повторно он не заменяется.
    out = replace(text, matches, lambda m: "msk1-new" if not m.parts else "MSK1.example")
    assert out == "HOST msk1.example, msk1-new"


def test_replace_upper_case_found() -> None:
    assert replace("CORP\\JDOE", [Match(0, 9, "user", "CORP\\JDOE")], lambda m: "DOM1\\user-0001") == "DOM1\\USER-0001"


def test_replace_secret_label_ignores_case() -> None:
    # Псевдоним секрета — метка формата <secret-xxxxxxxx>, регистр значения в неё не переносится.
    out = replace("key AKIAIOSFODNN7EXAMPLE", [Match(4, 24, "secret", "AKIAIOSFODNN7EXAMPLE")], lambda m: "<secret-0a1b2c3d>")
    assert out == "key <secret-0a1b2c3d>"
