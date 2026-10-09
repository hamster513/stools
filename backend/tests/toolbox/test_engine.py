"""Ход очистки (спека §3, §5): скан, замена включённых, стабильность, самопроверка, обратный перевод."""
from __future__ import annotations

import dataclasses
import io
import json
import re
import time
import zipfile
from pathlib import Path
from typing import Any

import pytest

from api.modules.toolbox.core.scrub.engine import VerifyError, _placed, apply, reverse, scan, verify
from api.modules.toolbox.core.scrub.types import KINDS, Ctx, Finding, Match
from tests.toolbox.synthetic import CTX, TEXT, MemoryAliases

#: Номер сборки, похожий на публичный адрес: найдётся, но без галочки.
SOURCE = TEXT + "2026-10-08 10:00:10 agent build 7.2.3.4\n"
#: Настоящие включённые значения — ни одно не должно остаться в результате.
REAL = (
    "10.1.2.15", "host01.", "corp.test", "corp\\", "jdoe", "S-1-5-21-111-222-333", "2001:4860::8888",
    "00:1a:2b:3c:4d:5e", "Qwerty123!", "am9lOnNlY3JldA==", "AKIAIOSFODNN7EXAMPLE", "ivanov", "acme",
)


#: Словарь со стенда: два домена AD, NetBIOS-имена без точки, хостов в словаре нет; corp.test — только авто.
STAND = Ctx(domains=frozenset({"corp.local", "corp", "test.internal", "test"}), hosts=frozenset(), users=frozenset(),
            words={}, subnets=[])
STAND_TEXT = "logon host01.corp.test (10.1.2.15) user CORP\\jdoe; see srv-db01.corp.test\nmail from jdoe@corp.test\n"


@pytest.fixture
def source(tmp_path: Path) -> Path:
    path = tmp_path / "log.txt"
    path.write_text(SOURCE, encoding="utf-8")
    return path


def by_value(findings: list[Finding]) -> dict[tuple[str, str], Finding]:
    return {(f.kind, f.value_key): f for f in findings}


def scrubbed_with(source: Path, target: Path, findings: list[Finding], aliases: MemoryAliases, ctx: Ctx) -> str:
    apply(source, target, findings, ctx, aliases)
    return target.read_text(encoding="utf-8")


def scrubbed(source: Path, target: Path, findings: list[Finding], aliases: MemoryAliases) -> str:
    return scrubbed_with(source, target, findings, aliases, CTX)


def test_scan_finds_every_kind_with_counts_and_contexts(source: Path) -> None:
    result = scan(source, CTX, MemoryAliases())
    found = by_value(result.findings)
    assert {kind for kind, _ in found} == set(KINDS)
    assert [e.path for e in result.entries] == ["log.txt"]
    host = found[("host", "host01")]
    assert host.count == 1 and host.alias == "host-0001" and host.first_file == "log.txt"
    assert len(host.contexts) == 1 and "logon host01.corp.test (10.1.2.15)" in host.contexts[0]
    assert all(len(c) <= 80 for f in result.findings for c in f.contexts)
    # Составные раскладываются на части: домен из FQDN и e-mail, учётка из CORP\jdoe и e-mail.
    assert found[("domain", "corp.test")].count == 2
    assert found[("user", "jdoe")].count == 2
    assert found[("domain", "corp")].alias == "DOM2"
    assert found[("word", "acme")].alias == "Contoso"
    assert found[("secret", "Qwerty123!")].alias.startswith("<secret-")


def test_scan_unchecks_auto_domain_and_version_like_address(source: Path) -> None:
    found = by_value(scan(source, CTX, MemoryAliases()).findings)
    auto = found[("domain", "example.test")]
    assert auto.auto and not auto.checked
    assert not found[("ip4", "7.2.3.4")].checked
    assert found[("host", "host01")].checked and found[("ip4", "10.1.2.15")].checked


@pytest.mark.parametrize("data", [{"10.1.2.3": {"addr": "10.1.2.3"}}, {"hosts": {"10.1.2.3": "x"}}])
def test_address_in_json_key_is_found_replaced_and_verified(tmp_path: Path, data: dict[str, Any]) -> None:
    # Адрес в имени ключа JSON — тоже адрес: иначе apply оставил бы его, а самопроверка нашла бы дословно.
    path = tmp_path / "keys.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    aliases = MemoryAliases()
    findings = scan(path, CTX, aliases).findings
    assert [(f.kind, f.value, f.checked) for f in findings] == [("ip4", "10.1.2.3", True)]
    apply(path, tmp_path / "out.json", findings, CTX, aliases)
    assert "10.1.2.3" not in (tmp_path / "out.json").read_text(encoding="utf-8")
    assert verify(tmp_path / "out.json", findings, CTX) == []


def test_scan_skips_addresses_under_version_keys(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"version": "10.1.2.3"}), encoding="utf-8")
    assert scan(path, CTX, MemoryAliases()).findings == []


def test_apply_leaves_no_checked_real_value(source: Path, tmp_path: Path) -> None:
    aliases = MemoryAliases()
    findings = scan(source, CTX, aliases).findings
    entries, counts = apply(source, tmp_path / "out.txt", findings, CTX, aliases)
    out = (tmp_path / "out.txt").read_text(encoding="utf-8")
    assert [r for r in REAL if r.lower() in out.lower()] == []
    assert re.search(r"password=<secret-[0-9a-f]{8}>", out)
    # Без галочки — на месте.
    assert "build 7.2.3.4" in out and "mail.example.test" in out
    assert "host011" in out and "127.0.0.1" in out
    assert [e.kind for e in entries] == ["text"]
    assert counts["host"] == 1 and counts["user"] == 2 and counts["domain"] == 3


def test_second_run_with_same_table_is_byte_identical(source: Path, tmp_path: Path) -> None:
    aliases = MemoryAliases()
    apply(source, tmp_path / "1.txt", scan(source, CTX, aliases).findings, CTX, aliases)
    apply(source, tmp_path / "2.txt", scan(source, CTX, aliases).findings, CTX, aliases)
    assert (tmp_path / "1.txt").read_bytes() == (tmp_path / "2.txt").read_bytes()


def test_table_holds_exactly_met_checked_values_without_secrets(source: Path, tmp_path: Path) -> None:
    aliases = MemoryAliases()
    findings = scan(source, CTX, aliases).findings
    assert aliases.table == {}  # скан ничего не записывает
    apply(source, tmp_path / "out.txt", findings, CTX, aliases)
    expected = {(f.kind, f.value_key) for f in findings if f.checked and f.kind != "secret"}
    assert set(aliases.table) == expected
    assert not any(kind == "secret" for kind, _ in aliases.table)
    assert aliases.table[("host", "host01")] == "host-0001"


def test_unchecked_value_stays(source: Path, tmp_path: Path) -> None:
    aliases = MemoryAliases()
    findings = [dataclasses.replace(f, checked=False) if f.value_key == "host01" else f
                for f in scan(source, CTX, aliases).findings]
    out = scrubbed(source, tmp_path / "out.txt", findings, aliases)
    assert "logon host01.dom1.example" in out
    assert ("host", "host01") not in aliases.table


def test_verify_is_empty_on_honest_result_and_catches_leftover(source: Path, tmp_path: Path) -> None:
    aliases = MemoryAliases()
    findings = scan(source, CTX, aliases).findings
    apply(source, tmp_path / "out.txt", findings, CTX, aliases)
    assert verify(tmp_path / "out.txt", findings, CTX) == []

    # Подложенная замена: псевдоним host01 — он сам.
    planted = [dataclasses.replace(f, alias=f.value) if f.value_key == "host01" else f for f in findings]
    apply(source, tmp_path / "bad.txt", planted, CTX, MemoryAliases())
    left = verify(tmp_path / "bad.txt", planted, CTX)
    assert [(f.kind, f.value_key, f.count, f.first_file) for f in left] == [("host", "host01", 1, "bad.txt")]


def test_reverse_restores_everything_but_secrets(tmp_path: Path) -> None:
    # Имена внутри имён файлов: «-» и «_» — границы и в словаре, и в обратном переводе.
    source = tmp_path / "log.txt"
    source.write_text(SOURCE + "2026-10-08 10:00:11 files host01_notes CORP_backup host01-notes.txt\n", encoding="utf-8")
    aliases = MemoryAliases()
    findings = scan(source, CTX, aliases).findings
    _, counts = apply(source, tmp_path / "out.txt", findings, CTX, aliases)
    out = (tmp_path / "out.txt").read_text(encoding="utf-8")
    secrets_only = [f if f.kind == "secret" else dataclasses.replace(f, checked=False) for f in findings]
    expected = scrubbed(source, tmp_path / "secrets.txt", secrets_only, MemoryAliases())
    text, replaced = reverse(out, aliases.pairs())
    assert text == expected
    assert replaced == sum(counts.values()) - counts["secret"]
    assert "host-0001_notes DOM2_backup host-0001-notes.txt" in out
    assert reverse("nothing here", []) == ("nothing here", 0)


def zipped(path: Path, members: dict[str, bytes]) -> Path:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    path.write_bytes(out.getvalue())
    return path


def test_bare_user_is_replaced_and_its_leftover_caught(tmp_path: Path) -> None:
    # Учёток в словаре нет: jdoe известен только из CORP\jdoe, но голый jdoe рядом — та же учётка.
    source = tmp_path / "log.txt"
    source.write_text("logon CORP\\jdoe ok\nuser jdoe again\n", encoding="utf-8")
    aliases = MemoryAliases()
    findings = scan(source, CTX, aliases).findings
    out = scrubbed(source, tmp_path / "out.txt", findings, aliases)
    assert out == "logon DOM1\\user-0001 ok\nuser user-0001 again\n"
    assert verify(tmp_path / "out.txt", findings, CTX) == []
    leak = tmp_path / "leak.txt"
    leak.write_text(out.replace("user user-0001", "user jdoe"), encoding="utf-8")
    assert [(f.kind, f.value_key) for f in verify(leak, findings, CTX)] == [("user", "jdoe")]


def test_host_in_zip_member_names_is_replaced_and_checked(tmp_path: Path) -> None:
    source = zipped(tmp_path / "in.zip", {"host01-notes.txt": b"a\n", "host01_notes.txt": b"b\n"})
    aliases = MemoryAliases()
    findings = scan(source, CTX, aliases).findings
    assert by_value(findings)[("host", "host01")].count == 2
    apply(source, tmp_path / "out.zip", findings, CTX, aliases)
    with zipfile.ZipFile(tmp_path / "out.zip") as zf:
        assert zf.namelist() == ["host-0001-notes.txt", "host-0001_notes.txt"]
    assert verify(tmp_path / "out.zip", findings, CTX) == []
    assert [(f.kind, f.value_key, f.count) for f in verify(source, findings, CTX)] == [("host", "host01", 2)]


def test_verify_fails_closed_on_missing_or_broken_result(source: Path, tmp_path: Path) -> None:
    findings = scan(source, CTX, MemoryAliases()).findings
    with pytest.raises(VerifyError):
        verify(tmp_path / "missing.zip", findings, CTX)
    broken = tmp_path / "broken.zip"
    broken.write_bytes(b"PK\x03\x04 truncated")
    with pytest.raises(VerifyError):
        verify(broken, findings, CTX)


def test_name_of_skipped_member_is_not_counted(tmp_path: Path) -> None:
    source = zipped(tmp_path / "in.zip", {"host01.bin": b"\x00\x01", "x.txt": b"host01\n"})
    aliases = MemoryAliases()
    findings = scan(source, CTX, aliases).findings
    _, counts = apply(source, tmp_path / "out.zip", findings, CTX, aliases)
    assert counts == {"host": 1}


def test_reverse_respects_word_boundaries() -> None:
    pairs = [("word-0001", "Ivanov"), ("host-0001", "host01")]
    assert reverse("word-0001 word-00012 host-0001x", pairs) == ("Ivanov word-00012 host-0001x", 1)


@pytest.mark.parametrize(("line", "kind", "value"), [
    ("logon CORP\\user ok\n", "user", "user"),
    ("seen host.corp.test\n", "host", "host"),
    ("logon EXAMPLE\\jdoe from mail.corp.test\n", "domain", "example"),
    # dom1.example — псевдоним corp.test, выданный раньше настоящего DOM1 (он получит DOM2).
    ("mail.corp.test logon DOM1\\jdoe\n", "domain", "dom1"),
    ("password: password\n", "secret", "password"),
    ("note word here, password: Qwerty123!\n", "word", "word"),
])
def test_verify_does_not_catch_its_own_aliases_or_keywords(tmp_path: Path, line: str, kind: str, value: str) -> None:
    ctx = dataclasses.replace(CTX, domains=CTX.domains | {"example", "dom1"},
                              words={**CTX.words, "word": ""} if kind == "word" else CTX.words)
    source = tmp_path / "log.txt"
    source.write_text(line, encoding="utf-8")
    aliases = MemoryAliases(ctx)
    findings = scan(source, ctx, aliases).findings
    assert (kind, value) in by_value(findings) and by_value(findings)[(kind, value)].checked
    apply(source, tmp_path / "out.txt", findings, ctx, aliases)
    assert verify(tmp_path / "out.txt", findings, ctx) == []
    # Настоящий остаток по-прежнему ловится.
    leak = tmp_path / "leak.txt"
    leak.write_text((tmp_path / "out.txt").read_text(encoding="utf-8") + f"left {line}", encoding="utf-8")
    assert (kind, value) in {(f.kind, f.value_key) for f in verify(leak, findings, ctx)}


def test_verify_literal_hit_inside_unrelated_detector_span_is_caught(source: Path, tmp_path: Path) -> None:
    findings = scan(source, CTX, MemoryAliases()).findings
    leak = tmp_path / "leak.txt"
    leak.write_text("token=host01_backup\n", encoding="utf-8")
    assert ("host", "host01") in {(f.kind, f.value_key) for f in verify(leak, findings, CTX)}


def test_verify_literal_hit_with_unicode_case_fold(tmp_path: Path) -> None:
    findings = [Finding("user", "jsmith", "jsmith", "user-0001")]
    leak = tmp_path / "leak.txt"
    leak.write_text("by j\u017fmith\n", encoding="utf-8")
    assert [(f.kind, f.value_key) for f in verify(leak, findings, CTX)] == [("user", "jsmith")]


def test_verify_hit_extending_past_own_alias_is_caught(tmp_path: Path) -> None:
    # Псевдоним слова «Bank» — часть настоящих bankov и bank-srv01: они длиннее псевдонима, это остатки.
    findings = [
        Finding("word", "Acme", "acme", "Bank"),
        Finding("user", "bankov", "bankov", "user-0001"),
        Finding("host", "bank-srv01", "bank-srv01", "host-0001"),
        Finding("domain", "CORP", "corp", "DOM1"),
        Finding("domain", "dom1-dc", "dom1-dc", "DOM2"),
    ]
    leak = tmp_path / "leak.txt"
    leak.write_text("logon bankov from bank-srv01 via Bank\nDOM1\\user-0001 at dom1-dc\n", encoding="utf-8")
    assert sorted((f.kind, f.value_key) for f in verify(leak, findings, CTX)) == [
        ("domain", "dom1-dc"), ("host", "bank-srv01"), ("user", "bankov"),
    ]


def test_verify_many_aliases_is_fast(tmp_path: Path) -> None:
    """Сторож производительности: границы общие на всю альтернацию, иначе regex теряет префиксную
    оптимизацию (было 34 с/МБ на 2000 псевдонимах)."""
    findings = [Finding("host", f"realhost{i}", f"realhost{i}", f"host-{i:04d}") for i in range(2000)]
    line = " ".join(f"seen host-{i:04d} ok" for i in range(0, 2000, 7)) + "\n"
    result = tmp_path / "out.txt"
    result.write_text(line * (512 * 1024 // len(line) + 1), encoding="utf-8")
    started = time.perf_counter()
    assert verify(result, findings, CTX) == []
    assert time.perf_counter() - started < 5


def test_placed_rejects_composite_not_at_edges() -> None:
    # Части составного лежат по его краям; другая форма должна упасть, а не проверить чужое место —
    # и без настоящего значения в тексте ошибки: он попадает в job.error, который видят все роли.
    m = Match(0, 18, "host", "srv-db01.corp.test", (("host", "srv-db01"), ("domain", "corp.test")))
    assert [(k, v) for k, v, _, _ in _placed(m, "srv-db01.corp.test", "a.txt")] == [("host", "srv-db01"), ("domain", "corp.test")]
    odd = Match(0, 18, "host", "srv-db01.corp.test", (("host", "db01"), ("domain", "corp.test")))
    with pytest.raises(VerifyError) as info:
        _placed(odd, "srv-db01.corp.test", "a.txt")
    assert str(info.value) == "a.txt: составное совпадение не на своём месте"


def test_stand_netbios_in_dictionary_does_not_leak_host_names(tmp_path: Path) -> None:
    # Со стенда: NetBIOS «test» резал host01.corp.test на host01.corp + test; когда авто-домен corp.test
    # включали, apply собирал host01.dom3.example — имя хоста утекало, а самопроверка молчала.
    source = tmp_path / "log.txt"
    source.write_text(STAND_TEXT, encoding="utf-8")
    aliases = MemoryAliases(STAND)
    found = by_value(scan(source, STAND, aliases).findings)
    assert ("host", "host01.corp") not in found and ("domain", "test") not in found
    assert found[("host", "host01")].auto and not found[("host", "host01")].checked
    # corp.test подтверждён e-mail jdoe@corp.test — как на стенде, где он был включён.
    assert found[("domain", "corp.test")].count == 3 and found[("domain", "corp.test")].checked
    findings = [dataclasses.replace(f, checked=True) for f in found.values()]
    out = scrubbed_with(source, tmp_path / "out.txt", findings, aliases, STAND)
    assert not re.search(r"host01|srv-db01|corp\.test|jdoe", out, re.IGNORECASE), out
    assert verify(tmp_path / "out.txt", findings, STAND) == []
    leak = tmp_path / "leak.txt"
    leak.write_text(out + "seen host01\n", encoding="utf-8")
    assert [(f.kind, f.value_key) for f in verify(leak, findings, STAND)] == [("host", "host01")]


def test_checked_auto_host_without_its_domain_is_replaced_alone(tmp_path: Path) -> None:
    source = tmp_path / "log.txt"
    source.write_text("logon host01.corp.test\n", encoding="utf-8")
    aliases = MemoryAliases(STAND)
    findings = [dataclasses.replace(f, checked=f.kind == "host") for f in scan(source, STAND, aliases).findings]
    out = scrubbed_with(source, tmp_path / "out.txt", findings, aliases, STAND)
    assert out == "logon host-0001.corp.test\n"
    assert verify(tmp_path / "out.txt", findings, STAND) == []


@pytest.mark.parametrize(("ctx", "line", "kind", "value"), [
    (dataclasses.replace(STAND, domains=frozenset({"msk.corp.local", "msk"})), "dc msk.corp.local up\n", "domain", "msk.corp.local"),
    (dataclasses.replace(STAND, domains=frozenset({"ad.company.ru", "ad"})), "domain ad.company.ru ok\n", "domain", "ad.company.ru"),
    (dataclasses.replace(STAND, hosts=frozenset({"srv-db01.other.org"})), "see srv-db01.other.org\n", "host", "srv-db01.other.org"),
])
def test_dictionary_whole_name_is_one_checked_finding_and_replaced(tmp_path: Path, ctx: Ctx, line: str, kind: str,
                                                                   value: str) -> None:
    source = tmp_path / "log.txt"
    source.write_text(line, encoding="utf-8")
    aliases = MemoryAliases(ctx)
    findings = scan(source, ctx, aliases).findings
    assert [(f.kind, f.value, f.checked, f.auto) for f in findings] == [(kind, value, True, False)]
    out = scrubbed_with(source, tmp_path / "out.txt", findings, aliases, ctx)
    assert value not in out and verify(tmp_path / "out.txt", findings, ctx) == []


def test_verify_catches_short_name_of_checked_fqdn_host(tmp_path: Path) -> None:
    # Хост из словаря — FQDN (asset.fqdn): голое короткое имя в результате — тот же хост, остаток.
    findings = [Finding("host", "srv-db01.corp.test", "srv-db01.corp.test", "host-0001")]
    leak = tmp_path / "leak.txt"
    leak.write_text("node srv-db01 up, srv-db011 is another, host-0001 ok\n", encoding="utf-8")
    assert [(f.kind, f.value_key, f.count) for f in verify(leak, findings, STAND)] == [("host", "srv-db01.corp.test", 1)]
