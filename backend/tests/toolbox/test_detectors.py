"""Детекторы движка очистки (спека §1): каждый находит своё и не трогает служебное."""
from __future__ import annotations

import dataclasses
import random
import time
from collections import Counter
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from itertools import pairwise

import pytest

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
    assert list(find_domains("report.final.txt corporate xcorp corp2", CTX)) == []
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


def test_hosts_fqdn_with_dictionary_domain_deeper_in_name() -> None:
    [fqdn] = [m for m in find_hosts("at msk1.sub.corp.test now", CTX) if m.parts]
    assert (fqdn.start, fqdn.end) == (3, 21)
    assert fqdn.parts == (("host", "msk1.sub"), ("domain", "corp.test"))
    [whole] = detect("msk1.sub.corp.test", CTX)
    assert whole.kind == "host" and whole.parts == fqdn.parts


def test_hosts_respect_word_boundaries_and_unconfirmed_domains() -> None:
    assert list(find_hosts("host011 xhost01", CTX)) == []
    # Домен не из словаря — авто-домен из двух последних меток, составное целиком авто (без галочки).
    [fqdn] = find_hosts("web7.other.org", CTX)
    assert fqdn.auto and fqdn.parts == (("host", "web7"), ("domain", "other.org"))
    assert list(find_hosts("report.final.txt two.labels", CTX)) == []
    # Словарный хост внутри авто-FQDN: составное есть, и словарное совпадение тоже.
    found = list(find_hosts("msk1.other.org", CTX))
    assert [(m.value, m.auto) for m in found] == [("msk1.other.org", True), ("msk1", False)]


def test_dictionary_domain_and_dictionary_host_are_not_split_by_auto_composite() -> None:
    # Словарный домен из трёх меток целиком — домен, а не хост msk + авто-домен corp.local (host старше domain
    # по приоритету, и настоящий домен AD уцелел бы без галочки).
    ctx = dataclasses.replace(CTX, domains=frozenset({"msk.corp.local", "msk"}), hosts=frozenset())
    assert list(find_hosts("msk.corp.local", ctx)) == []
    assert [(m.kind, m.value, m.auto) for m in detect("msk.corp.local", ctx)] == [("domain", "msk.corp.local", False)]
    ctx = dataclasses.replace(CTX, domains=frozenset({"ad.company.ru", "ad"}), hosts=frozenset())
    assert [(m.kind, m.value, m.auto) for m in detect("domain ad.company.ru ok", ctx)] == [("domain", "ad.company.ru", False)]
    # Словарный хост-FQDN с доменом не из словаря — один хост целиком, не srv-db01 + other.org без галочек.
    ctx = dataclasses.replace(CTX, domains=frozenset(), hosts=frozenset({"srv-db01.other.org"}))
    assert [(m.value, m.parts, m.auto) for m in find_hosts("see srv-db01.other.org", ctx)] == [("srv-db01.other.org", (), False)]


def test_hosts_netbios_is_never_fqdn_suffix_and_longest_dotted_domain_wins() -> None:
    # Словарь со стенда: NetBIOS «test» без точки резал host01.corp.test на host01.corp + test — host01 утекал.
    ctx = dataclasses.replace(CTX, domains=frozenset({"corp", "test", "corp.local"}), hosts=frozenset())
    [fqdn] = find_hosts("logon host01.corp.test", ctx)
    assert fqdn.parts == (("host", "host01"), ("domain", "corp.test")) and fqdn.auto
    ctx = dataclasses.replace(CTX, domains=frozenset({"test.internal", "test"}), hosts=frozenset())
    [fqdn] = find_hosts("dc1.test.internal", ctx)
    assert fqdn.parts == (("host", "dc1"), ("domain", "test.internal")) and not fqdn.auto
    # Несколько словарных доменов подходят суффиксом — побеждает самый длинный.
    ctx = dataclasses.replace(CTX, domains=frozenset({"corp.test", "sub.corp.test"}))
    [fqdn] = [m for m in find_hosts("msk1.sub.corp.test", ctx) if m.parts]
    assert fqdn.parts == (("host", "msk1"), ("domain", "sub.corp.test")) and not fqdn.auto
    # NetBIOS по-прежнему находится в учётке и голым; FQDN из двух меток с ним — не хост.
    ctx = dataclasses.replace(CTX, domains=frozenset({"corp", "test"}))
    assert [(m.value, m.parts) for m in find_users("TEST\\jdoe", ctx)] == [
        ("TEST\\jdoe", (("domain", "TEST"), ("user", "jdoe"))),
    ]
    assert values(find_domains("domain TEST ok", ctx)) == ["TEST"]
    assert [m for m in find_hosts("host01.test", ctx) if m.parts] == []


def test_dictionary_dash_and_underscore_are_boundaries_longest_first() -> None:
    # Имена файлов в выгрузках: host01-notes.txt, host01_notes.txt — имя хоста внутри.
    ctx = dataclasses.replace(CTX, hosts=CTX.hosts | {"srv"})
    found = list(find_hosts("host01-b host01-notes.txt host01_notes srv-db01 srv_x", ctx))
    assert values(found) == ["host01", "host01", "host01", "srv-db01", "srv"]
    assert values(find_domains("corp-x x.corp_y", CTX)) == ["corp", "corp"]
    assert values(find_users("jdoe_old", with_users("jdoe"))) == ["jdoe"]


def test_users_composite_netbios_and_email() -> None:
    found = list(find_users("CORP\\jdoe and jdoe@corp.test", CTX))
    assert [(m.value, m.parts) for m in found] == [
        ("CORP\\jdoe", (("domain", "CORP"), ("user", "jdoe"))),
        ("jdoe@corp.test", (("user", "jdoe"), ("domain", "corp.test"))),
    ]


def test_users_email_with_plus_tag() -> None:
    [found] = find_users("to a.b+tag@corp.test.", CTX)
    assert found.value == "a.b+tag@corp.test"
    assert found.parts == (("user", "a.b+tag"), ("domain", "corp.test"))


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


@pytest.mark.parametrize("value", [
    "null", "None", "NIL", "true", "False", "yes", "no", "required", "empty", "REDACTED", "***", "********",
    "xxxx", "XXXXXX", "<masked>", "<hidden>", "${DB_PASS}", "%PASSWORD%", "$SECRET",
])
def test_keyword_placeholders_are_not_secrets(value: str) -> None:
    assert list(find_secrets(f"token: {value}\npassword={value}\nAuthorization: Bearer {value}", CTX)) == []


def test_keyword_real_values_next_to_placeholder_words_are_secrets() -> None:
    text = "token: nullable-Qx81\npassword=xxxxQ7!\npwd=$ecretW0rd"
    assert sorted(values(find_secrets(text, CTX))) == ["$ecretW0rd", "nullable-Qx81", "xxxxQ7!"]


def test_secrets_skip_plain_text_and_long_lines() -> None:
    assert list(find_secrets("hello world, logon host01 ok", CTX)) == []
    assert list(find_secrets("x" * 4100 + " AKIAIOSFODNN7EXAMPLE", CTX)) == []


def test_secrets_keywords_on_long_lines() -> None:
    # Лимит длины — только для detect-secrets; пароль по ключевому слову ищется в любой строке.
    long_line = "x" * 4100 + " password=Qwerty123!"
    assert [(m.start, m.value) for m in find_secrets(long_line, CTX)] == [(4110, "Qwerty123!")]


def test_secrets_only_at_their_place() -> None:
    assert [(m.start, m.end) for m in find_secrets("secret=1234 port 12345", CTX)] == [(7, 11)]
    assert values(find_secrets("token: null1, other: null1", CTX)) == ["null1"]
    # «required» теперь пустышка (см. test_keyword_placeholders_are_not_secrets) — место проверяется на пароле.
    found = list(find_secrets("Password: Winter2026 by policy, Winter2026", CTX))
    assert [(m.start, m.value) for m in found] == [(10, "Winter2026")]


def test_secrets_right_after_equals_sign() -> None:
    # Вид KEY=value (env, ini): ключевого слова нет, значение находит detect-secrets.
    [found] = find_secrets("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", CTX)
    assert (found.start, found.value) == (18, "AKIAIOSFODNN7EXAMPLE")
    assert values(find_secrets("x=8f14e45fceea167a5a36dedd4bea25", CTX)) == ["8f14e45fceea167a5a36dedd4bea25"]


def test_secrets_skip_bare_file_hashes() -> None:
    for n in (32, 40, 64):
        digest = ("8f14e45fceea167a5a36dedd4bea2543" * 2)[:n]
        assert list(find_secrets(f'"sha": "{digest}"', CTX)) == []
    sha256 = "8f14e45fceea167a5a36dedd4bea2543" * 2
    assert values(find_secrets(f"token: {sha256}", CTX)) == [sha256]
    # Другая длина — не хеш файла: высокоэнтропийная hex-строка остаётся секретом.
    assert values(find_secrets('x = "8f14e45fceea167a5a36dedd4bea25"', CTX)) == ["8f14e45fceea167a5a36dedd4bea25"]


def test_secrets_in_parallel_threads() -> None:
    text = "aws AKIAIOSFODNN7EXAMPLE\nx = \"8f14e45fceea167a5a36dedd4bea25\"\n" * 20
    expected = list(find_secrets(text, CTX))
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: list(find_secrets(text, CTX)), range(16)))
    assert all(r == expected for r in results) and len(expected) == 40


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
        ("host", "mail.example.test"),
    }
    assert by_value == expected
    texts = [TEXT[m.start:m.end] for m in found]
    assert "host01" not in texts  # внутри host011 и внутри FQDN — не отдельное совпадение
    assert not any(t in ("fe80::1", "127.0.0.1", "12.3.0.0") for t in texts)
    # Хост с авто-доменом — составное авто: и mail, и example.test в предпросмотре без галочки.
    [auto] = [m for m in found if m.auto]
    assert auto.value == "mail.example.test" and auto.parts == (("host", "mail"), ("domain", "example.test"))


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


def test_secret_under_json_password_key() -> None:
    # В обходе JSON кусок — само значение, «password:» рядом нет: ключевое слово приходит ключом.
    [found] = find_secrets("hunter22", dataclasses.replace(CTX, json_key="db_password"))
    assert (found.start, found.end, found.value) == (0, 8, "hunter22")
    assert list(find_secrets("null", dataclasses.replace(CTX, json_key="token"))) == []
    assert list(find_secrets("abc", dataclasses.replace(CTX, json_key="Password"))) == []
    assert list(find_secrets("hunter22", dataclasses.replace(CTX, json_key="__key__"))) == []


def test_secret_key_only_as_whole_name_or_last_segment() -> None:
    # Ключевое слово — целое имя ключа или его последний сегмент через «_»/«-»; password_policy,
    # token_count, secret_question, tokenizer — не пароли.
    for key in ("password", "db_password", "api-key", "access_token", "Authorization"):
        [found] = find_secrets("hunter22", dataclasses.replace(CTX, json_key=key))
        assert found.value == "hunter22", key
    for key in ("password_policy", "token_count", "secret_question", "tokenizer"):
        assert list(find_secrets("enabled", dataclasses.replace(CTX, json_key=key))) == [], key


def test_value_with_spaces_under_secret_like_key_is_scanned_normally() -> None:
    # У пароля нет пробелов: значение с пробелами — обычный текст, в нём ищутся учётки, хосты и адреса,
    # а не один секрет на всё целиком (он перекрыл бы их и снял бы с замены).
    text = "Issued to jsmith@corp.test from srv-db01.corp.test 10.1.2.3"
    found = detect(text, dataclasses.replace(CTX, json_key="token_description"))
    assert [(m.kind, m.value) for m in found] == [
        ("user", "jsmith@corp.test"), ("host", "srv-db01.corp.test"), ("ip4", "10.1.2.3"),
    ]
    found = detect(text, dataclasses.replace(CTX, json_key="password"))
    assert [(m.kind, m.value) for m in found] == [
        ("user", "jsmith@corp.test"), ("host", "srv-db01.corp.test"), ("ip4", "10.1.2.3"),
    ]


def _log_corpus() -> list[str]:
    """~0,5 МБ лога: случайные строки синтетики с уникальным хвостом, как в профиле скорости (5863 строки)."""
    rng = random.Random(20261009)
    source = TEXT.splitlines()
    lines: list[str] = []
    size = 0
    while size < 512_000:
        line = f"{rng.choice(source)} id={len(lines)} host{len(lines)}.corp.test"
        lines.append(line)
        size += len(line) + 1
    return lines


def test_secrets_on_log_corpus_same_as_before_direct_plugin_calls() -> None:
    # Эталон снят со старой реализации (scan_line detect-secrets) до перехода на прямые вызовы плагинов.
    lines = _log_corpus()
    found = Counter(m.value for line in lines for m in find_secrets(line, CTX))
    assert found == {"AKIAIOSFODNN7EXAMPLE": 633, "Qwerty123!": 631, "am9lOnNlY3JldA==": 628}
    assert Counter(m.value for m in find_secrets("\n".join(lines), CTX)) == found


@pytest.mark.parametrize(("line", "expected"), [
    # hex: 9 символов уже могут пройти порог 3,0 бита — короче 16 строки пропускать нельзя.
    ("x=8f14e45fce end", []),
    ("ref 9d4e1f7a2c ok", [(4, "9d4e1f7a2c")]),
    ("sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709 md5 d41d8cd98f00b204e9800998ecf8427e", []),
    # base64: в кавычках, без кавычек; короткая строка в кавычках отменяет поиск без кавычек.
    ("cfg 'Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg' quoted", [(5, "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg")]),
    ("blob Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg end", [(5, "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg")]),
    ('name="ab" key Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg', []),
    (("mixed '0aF9' \"Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg==\" tail "
      "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
     [(14, "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg==")]),
    # Фильтры detect-secrets: uuid, последовательности, *_id, шаблоны, «$», allowlist.
    ("id 550e8400-e29b-41d4-a716-446655440000 ok", []),
    ("seq abcdefghijklmnopqrstuvwxyz0123456789 ABCDEF0123456789abcdef", []),
    ("user_id=8f14e45fceea167a session_id: 9b2c7d1e4f5a6b8c", []),
    ('v="${SOME_TOKEN_VALUE_HERE_1234}" w=<SomeValueFromVault12345678>', []),
    ("cost $8f14e45fceea167a5a3 total", [(6, "8f14e45fceea167a5a3")]),
    ("key=8f14e45fceea167a5a36 # pragma: allowlist secret", []),
    ("path C:\\Temp\\8f14e45fceea167a5a36dedd4bea2543\\setup.exe", []),
    ("registry HKLM\\SOFTWARE\\Classes\\CLSID\\{4234d49b-0245-4df3-b780-3893943456e1}\\InprocServer32", []),
    # Плагины-regex: JWT, приватный ключ, KeywordDetector, BasicAuth; публичный адрес — не секрет.
    ("jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
     [(69, "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")]),
    ("-----BEGIN RSA PRIVATE KEY-----", [(5, "BEGIN RSA PRIVATE KEY")]),
    ("private_key: 'abcd1234xyz'", [(14, "abcd1234xyz")]),
    ("url https://admin:pa55w0rd@host.example.test/path", [(18, "pa55w0rd")]),
    ("connect 8.8.8.8:53 and 203.0.113.7", []),
    ("ps1 $env:API_TOKEN=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg9x",
     [(9, "API_TOKEN=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg9x"), (19, "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg9x")]),
])
def test_secrets_detect_secrets_paths_same_as_before(line: str, expected: list[tuple[int, str]]) -> None:
    # Эталон снят со старой реализации через scan_line: плагины, порог энтропии и фильтры — те же.
    assert sorted((m.start, m.value) for m in find_secrets(line, CTX)) == expected


def test_detect_log_corpus_speed() -> None:
    # Через scan_line detect-secrets этот корпус шёл ~4,6 с (под cProfile ~12 с), напрямую — ~1,2 с.
    lines = _log_corpus()
    find_secrets("warm up", CTX)
    started = time.perf_counter()
    for line in lines:
        detect(line, CTX)
    assert time.perf_counter() - started < 4
