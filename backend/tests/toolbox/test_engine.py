"""Ход очистки (спека §3, §5): скан, замена включённых, стабильность, самопроверка, обратный перевод."""
from __future__ import annotations

import dataclasses
import gzip
import io
import json
import re
import time
import zipfile
from pathlib import Path
from typing import Any

import pytest

from api.modules.toolbox.core.scrub.detectors import detect
from api.modules.toolbox.core.scrub.engine import (
    Memo,
    Status,
    VerifyError,
    _placed,
    apply,
    reverse,
    scan,
    verify,
)
from api.modules.toolbox.core.scrub.types import KINDS, Ctx, Finding, Match
from tests.toolbox.synthetic import CTX, TEXT, MemoryAliases, ksc_like_ctx, ksc_like_export

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


def test_scan_apply_verify_report_their_phases(tmp_path: Path) -> None:
    source = zipped(tmp_path / "in.zip", {"a.log": SOURCE.encode(), "b.log": b"logon host01 again\n"})
    calls: list[Status] = []
    aliases = MemoryAliases()
    result = scan(source, CTX, aliases, progress=calls.append)
    scanned = [p for p in calls if p.phase == "scan"]
    assert scanned == calls and [p.entries_done for p in scanned][-1] == 2
    # Найдено — уникальных значений к этому месту: растёт и в конце равно итогу скана.
    assert [p.findings for p in scanned] == sorted(p.findings for p in scanned)
    assert scanned[-1].findings == len(result.findings) > 0

    calls.clear()
    apply(source, tmp_path / "out.zip", result.findings, CTX, aliases, progress=calls.append)
    assert calls and {p.phase for p in calls} == {"apply"} and calls[-1].entries_done == 2
    calls.clear()
    assert verify(tmp_path / "out.zip", result.findings, CTX, progress=calls.append) == []
    assert calls and {p.phase for p in calls} == {"verify"} and calls[-1].entries_done == 2
    assert calls[-1].source_pos == (tmp_path / "out.zip").stat().st_size


# --- симметрия apply и verify (стенд, задание №8: 4 остатка при 160 тыс. замен) --------------------

def test_address_equal_to_version_value_is_left_by_apply_and_not_flagged_by_verify(tmp_path: Path) -> None:
    # Включённый адрес встречается и целым значением под ключом *Version: find_ip4 под version/build не ищет
    # (номер версии, спека §1), apply оставляет — и дословный поиск самопроверки не должен его считать.
    data = {"hosts": [{"ip": "10.1.2.3"}], "plugins": [{"MinimalPluginVersion": "10.1.2.3", "KLHST_WKS_NAG_VERSION": "10.1.2.3"}]}
    path = tmp_path / "export.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    aliases = MemoryAliases()
    findings = scan(path, CTX, aliases).findings
    assert [(f.kind, f.value, f.count, f.checked) for f in findings] == [("ip4", "10.1.2.3", 1, True)]
    _, counts = apply(path, tmp_path / "out.json", findings, CTX, aliases)
    out = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert counts == {"ip4": 1} and out["hosts"][0]["ip"] != "10.1.2.3"
    assert out["plugins"] == data["plugins"]
    assert verify(tmp_path / "out.json", findings, CTX) == []
    # Тот же адрес под обычным ключом — остаток.
    leak = tmp_path / "leak.json"
    leak.write_text(json.dumps({**out, "relay": "10.1.2.3"}), encoding="utf-8")
    assert [(f.kind, f.value_key, f.count) for f in verify(leak, findings, CTX)] == [("ip4", "10.1.2.3", 1)]


def test_checked_netbios_domain_inside_unchecked_auto_host_is_replaced(tmp_path: Path) -> None:
    # Со стенда: NetBIOS-домен — метка внутри имени авто-хоста (site-corp.other.org). Составное побеждает
    # словарный домен на том же месте; хост без галочки, apply оставлял site-corp, а дословный поиск
    # самопроверки видел «corp» на границе «-». Голый site-corp без FQDN словарь разобрал бы — так и здесь.
    source = tmp_path / "log.txt"
    source.write_text("logon CORP\\jdoe at site-corp.other.org; mail jdoe@other.org\n", encoding="utf-8")
    aliases = MemoryAliases()
    found = by_value(scan(source, CTX, aliases).findings)
    assert found[("host", "site-corp")].auto and not found[("host", "site-corp")].checked
    assert found[("domain", "other.org")].checked and found[("domain", "corp")].checked
    findings = list(found.values())
    out = scrubbed(source, tmp_path / "out.txt", findings, aliases)
    assert out == "logon DOM1\\user-0001 at site-dom1.dom2.example; mail user-0001@dom2.example\n"
    assert verify(tmp_path / "out.txt", findings, CTX) == []
    assert ("host", "site-corp") not in aliases.table
    # Голое имя того же хоста в тексте — тот же разбор, та же замена.
    source.write_text("backup of site-corp done; CORP\\jdoe\n", encoding="utf-8")
    assert scrubbed(source, tmp_path / "out2.txt", findings, aliases) == "backup of site-dom1 done; DOM1\\user-0001\n"


def test_checked_value_inside_unchecked_dictionary_match_is_replaced(tmp_path: Path) -> None:
    # Хост из словаря снят владельцем, а домен внутри его имени включён: замена домена не зависит от галочки
    # хоста. Слово — тоже: внутри снятого секрета оно меняется.
    ctx = dataclasses.replace(CTX, hosts=CTX.hosts | {"dc-corp"})
    source = tmp_path / "log.txt"
    source.write_text("logon CORP\\jdoe at dc-corp; password=acme-Qwerty123! vendor Acme\n", encoding="utf-8")
    aliases = MemoryAliases(ctx)
    findings = [dataclasses.replace(f, checked=f.kind not in ("host", "secret")) for f in scan(source, ctx, aliases).findings]
    out = scrubbed_with(source, tmp_path / "out.txt", findings, aliases, ctx)
    assert out == "logon DOM1\\user-0001 at dc-dom1; password=contoso-Qwerty123! vendor Contoso\n"
    assert verify(tmp_path / "out.txt", findings, ctx) == []


def test_bare_short_name_of_checked_dotted_host_is_replaced_with_host_alias(tmp_path: Path) -> None:
    # Хост с точкой (msk1.sub из msk1.sub.corp.test): его короткое имя голым — тот же хост. Самопроверка
    # это уже ловила (A4), теперь и apply меняет на псевдоним хоста целиком; обратный перевод вернёт
    # host-0001 → msk1.sub, а не msk1 — это принято. msk11 и msk1 внутри слов — не трогаются.
    ctx = dataclasses.replace(STAND, domains=frozenset({"corp.test"}))
    source = tmp_path / "log.txt"
    source.write_text("seen msk1.sub.corp.test; share \\\\fs\\msk1\\logs; MSK1 up; msk11 and xmsk1 other\n", encoding="utf-8")
    aliases = MemoryAliases(ctx)
    found = by_value(scan(source, ctx, aliases).findings)
    assert set(found) == {("host", "msk1.sub"), ("domain", "corp.test")} and not found[("host", "msk1.sub")].auto
    findings = list(found.values())
    apply(source, tmp_path / "out.txt", findings, ctx, aliases)
    out = (tmp_path / "out.txt").read_text(encoding="utf-8")
    assert out == "seen host-0001.dom1.example; share \\\\fs\\host-0001\\logs; HOST-0001 up; msk11 and xmsk1 other\n"
    assert verify(tmp_path / "out.txt", findings, ctx) == []
    assert aliases.table == {("host", "msk1.sub"): "host-0001", ("domain", "corp.test"): "dom1.example"}
    assert reverse(out, aliases.pairs())[0] == "seen msk1.sub.corp.test; share \\\\fs\\msk1.sub\\logs; MSK1.SUB up; msk11 and xmsk1 other\n"
    leak = tmp_path / "leak.txt"
    leak.write_text(out + "node msk1 down\n", encoding="utf-8")
    assert [(f.kind, f.value_key, f.count) for f in verify(leak, findings, ctx)] == [("host", "msk1.sub", 1)]


def test_short_name_that_is_its_own_checked_host_keeps_its_own_alias(tmp_path: Path) -> None:
    # msk1 — отдельный хост словаря, и msk1.sub — тоже хост: голый msk1 получает свой псевдоним, не чужой.
    ctx = dataclasses.replace(STAND, domains=frozenset({"corp.test"}), hosts=frozenset({"msk1"}))
    source = tmp_path / "log.txt"
    source.write_text("seen msk1.sub.corp.test and msk1\n", encoding="utf-8")
    aliases = MemoryAliases(ctx)
    findings = scan(source, ctx, aliases).findings
    assert {(f.kind, f.value_key) for f in findings} == {("host", "msk1.sub"), ("host", "msk1"), ("domain", "corp.test")}
    out = scrubbed_with(source, tmp_path / "out.txt", findings, aliases, ctx)
    assert out == "seen host-0001.dom1.example and host-0002\n"
    assert verify(tmp_path / "out.txt", findings, ctx) == []


#: Документы с тремя закономерностями стенда поверх выгрузки KSC: значение под ключом *Version, равное
#: адресу; NetBIOS-домен (corp — 4 символа) в именах ключей и строках KLPRSS_Val на границах «_» и в имени
#: авто-хоста; хост с точкой, короткое имя которого встречается голым.
STAND_PATTERNS: dict[str, Any] = {
    "plugins": [{"MinimalPluginVersion": "10.1.2.15", "ProdVersion": "10.1.2.15"}],
    "KLPRSS_CORP_Settings": {"KLPRSS_Val": "C:\\Shares\\CORP_backup\\x", "CORP_path": {"KLPRSS_Val": "\\\\CORP\\share"}},
    "events": ["logon CORP\\user001 at mail-corp.other.org", "contact admin@other.org", "seen dc1.site.corp.local",
               "share \\\\fs\\dc1\\logs", "DC1 up", "relay 10.1.2.15 via ws00001"],
}


@pytest.fixture(scope="module")
def stand_corpus(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Ctx]:
    """Выгрузка KSC на 100 хостов и документы с закономерностями стенда — одним zip."""
    source = tmp_path_factory.mktemp("stand") / "export.zip"
    zipped(source, {
        "export.json": json.dumps(ksc_like_export(100), ensure_ascii=False).encode(),
        "patterns.json": json.dumps(STAND_PATTERNS).encode(),
        "notes.txt": "\n".join(STAND_PATTERNS["events"]).encode(),
    })
    return source, ksc_like_ctx(100)


@pytest.mark.parametrize("auto_hosts_checked", [True, False])
def test_apply_then_verify_is_clean_on_stand_corpus_and_planted_leak_fails(stand_corpus: tuple[Path, Ctx], tmp_path: Path,
                                                                            auto_hosts_checked: bool) -> None:
    # Свойство симметрии: всё, что самопроверка нашла бы дословно, apply уже заменил; что apply оставляет
    # намеренно (номер версии, авто-хост без галочки), самопроверка не считает. Как на стенде: без галочки
    # остаются только авто-хосты (или ничего).
    source, ctx = stand_corpus
    aliases = MemoryAliases(ctx)
    found = scan(source, ctx, aliases).findings
    findings = [dataclasses.replace(f, checked=auto_hosts_checked or not (f.auto and f.kind == "host")) for f in found]
    assert any(f.kind == "host" and f.auto for f in findings)  # mail-corp из mail-corp.other.org
    memo = Memo()
    target = tmp_path / "out.zip"
    apply(source, target, findings, ctx, aliases, memo=memo)
    assert verify(target, findings, ctx, memo=memo) == []
    with zipfile.ZipFile(target) as zf:
        patterns = json.loads(zf.read("patterns.json"))
        notes = zf.read("notes.txt").decode()
    assert patterns["plugins"] == STAND_PATTERNS["plugins"]  # номер версии на месте
    assert "corp" not in notes.lower() and "dc1" not in notes.lower() and "10.1.2.15" not in notes
    # Подложенная утечка в результат — по одному значению каждого вида из закономерностей.
    for line in ("seen dc1\n", "domain CORP\n", "relay 10.1.2.15\n", "user001\n"):
        leak = tmp_path / f"leak-{len(line)}.zip"
        with zipfile.ZipFile(target) as zf:
            zipped(leak, {**{n: zf.read(n) for n in zf.namelist()}, "leak.txt": line.encode()})
        assert verify(leak, findings, ctx, memo=memo) != [], line


# --- скорость на выгрузке KSC -------------------------------------------------------------------

KSC_HOSTS = 100


@pytest.fixture(scope="module")
def ksc_corpus(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Ctx]:
    """Выгрузка в стиле KSC на 100 хостов (~16 тыс. кусков, уникальных ~12%), как на стенде — в .json.gz."""
    source = tmp_path_factory.mktemp("ksc") / "export.json.gz"
    source.write_bytes(gzip.compress(json.dumps(ksc_like_export(KSC_HOSTS), ensure_ascii=False).encode()))
    return source, ksc_like_ctx(KSC_HOSTS)


def run_job(source: Path, target: Path, ctx: Ctx, *, enabled: bool) -> tuple[Any, ...]:
    """Скан, замена и самопроверка одним заданием; всё, что в них считается, — для сверки путей."""
    aliases = MemoryAliases(ctx)
    result = scan(source, ctx, aliases, memo=Memo(enabled=enabled))
    memo = Memo(enabled=enabled)  # общий у замены и самопроверки, как в сервисе
    entries, counts = apply(source, target, result.findings, ctx, aliases, memo=memo)
    left = verify(target, result.findings, ctx, memo=memo)
    return (
        [(f.kind, f.value_key, f.count, f.alias, f.checked, f.auto, f.first_file, f.contexts) for f in result.findings],
        result.chunks, [e.kind for e in entries], counts, [(f.kind, f.value_key, f.count) for f in left],
        dict(aliases.table), target.read_bytes(),
    )


def test_fast_path_gives_same_findings_bytes_and_leftovers_as_slow_path(ksc_corpus: tuple[Path, Ctx],
                                                                       tmp_path: Path) -> None:
    # Медленный путь — каждый кусок через detect и regex; быстрый — пропуск пустышек и кеш по тексту.
    source, ctx = ksc_corpus
    slow = run_job(source, tmp_path / "slow.json.gz", ctx, enabled=False)
    fast = run_job(source, tmp_path / "fast.json.gz", ctx, enabled=True)
    assert fast == slow
    findings, chunks, kinds, counts, left, table, _ = fast
    assert chunks > 10_000 and kinds == ["json"] and left == []
    assert {kind for kind, *_ in findings} == set(KINDS)
    assert counts["host"] > KSC_HOSTS and counts["secret"] > 0 and ("host", "ws00001") in table


def test_memo_skips_trivial_chunks_only_when_detect_would_find_nothing() -> None:
    # Пустышки (пустая строка, пробелы, короткие цифры) — те же находки, что у detect, под любым ключом,
    # и с цифровым именем в словаре (тогда пропуска нет).
    digits = dataclasses.replace(CTX, hosts=CTX.hosts | {"123"}, words={**CTX.words, "12": ""})
    chunks = ["", " ", "\n", "0", "123", "12345678", "123456789", "1234567890123456789012", "true", "null",
              *TEXT.splitlines(), "ws00001.corp.test", "AKIAIOSFODNN7EXAMPLE"]
    for ctx in (CTX, digits):
        find = Memo().bind(ctx)
        for json_key in ("", "__key__", "__name__", "octets", "password", "version", "token_version"):
            expected = [detect(text, dataclasses.replace(ctx, json_key=json_key)) for text in chunks]
            assert [find(json_key, text) for text in chunks] == expected, (json_key, ctx is digits)
            assert [find(json_key, text) for text in chunks] == expected  # и из кеша


def test_memo_is_shared_by_equal_ctx_and_cleared_by_another() -> None:
    memo = Memo()
    find = memo.bind(CTX)
    assert find("", "logon host01") == detect("logon host01", CTX) and memo.entries == 1
    memo.bind(dataclasses.replace(CTX, hosts=frozenset(CTX.hosts)))  # равный ctx — кеш живёт
    assert memo.entries == 1
    memo.bind(dataclasses.replace(CTX, words={}))
    assert memo.entries == 0
    find = Memo(enabled=False).bind(CTX)
    assert find("", "logon host01") == detect("logon host01", CTX)
    disabled = Memo(enabled=False)
    disabled.bind(CTX)("", "logon host01")
    assert disabled.entries == 0
    # Полный кеш: дальше ищется мимо него, находки те же.
    small = Memo(entries=1)
    find = small.bind(CTX)
    assert [find("", t) for t in ("logon host01", "sid S-1-5-21-1-2-3-500")] == [detect("logon host01", CTX), detect("sid S-1-5-21-1-2-3-500", CTX)]
    assert small.entries == 1


def test_ksc_corpus_job_is_fast(ksc_corpus: tuple[Path, Ctx], tmp_path: Path) -> None:
    """Сторож скорости: до кеша три прохода по этому корпусу шли ~4,5 с (5000 хостов — 377 с), теперь ~0,5 с."""
    source, ctx = ksc_corpus
    started = time.perf_counter()
    run_job(source, tmp_path / "out.json.gz", ctx, enabled=True)
    assert time.perf_counter() - started < 10


def test_alternation_survives_long_values_and_prefix_chains() -> None:
    """Свёртка в дерево была рекурсивной по символам: включённое значение длиннее ~1000 символов
    (длинный секрет из выгрузки) роняло verify с RecursionError. Набор-цепочка префиксов упирается
    уже в разбор регулярки — тогда отдаётся плоская альтернация. В обоих случаях совпадения те же."""
    import random
    import string

    from api.modules.toolbox.core.scrub.engine import _alternation, _nesting

    random.seed(7)
    long_value = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(3000))
    chain = ["a" * n for n in range(1, 700)]
    for values in ([long_value], chain, [long_value, "host01", "host0", "host011", "h"]):
        pattern = _alternation(values)
        folded = re.compile(pattern, re.IGNORECASE)
        flat = re.compile("|".join(re.escape(v) for v in sorted(set(values), key=len, reverse=True)), re.IGNORECASE)
        text = " ".join(random.choice(values) for _ in range(50)) + " xhost01 host0110 " + "a" * 800 + " " + long_value[:100]
        assert [m.span() for m in folded.finditer(text)] == [m.span() for m in flat.finditer(text)]
    assert _nesting(_alternation(chain)) == 0  # цепочка — плоская альтернация
    assert _nesting(r"a\(b(?:c(?:d))") == 2
