"""Ход очистки (спека §3, §5): скан, замена включённых, стабильность, самопроверка, обратный перевод."""
from __future__ import annotations

import dataclasses
import io
import json
import re
import zipfile
from pathlib import Path

import pytest

from api.modules.toolbox.core.scrub.engine import VerifyError, apply, reverse, scan, verify
from api.modules.toolbox.core.scrub.types import KINDS, Finding
from tests.toolbox.synthetic import CTX, TEXT, MemoryAliases

#: Номер сборки, похожий на публичный адрес: найдётся, но без галочки.
SOURCE = TEXT + "2026-10-08 10:00:10 agent build 7.2.3.4\n"
#: Настоящие включённые значения — ни одно не должно остаться в результате.
REAL = (
    "10.1.2.15", "host01.", "corp.test", "corp\\", "jdoe", "S-1-5-21-111-222-333", "2001:4860::8888",
    "00:1a:2b:3c:4d:5e", "Qwerty123!", "am9lOnNlY3JldA==", "AKIAIOSFODNN7EXAMPLE", "ivanov", "acme",
)


@pytest.fixture
def source(tmp_path: Path) -> Path:
    path = tmp_path / "log.txt"
    path.write_text(SOURCE, encoding="utf-8")
    return path


def by_value(findings: list[Finding]) -> dict[tuple[str, str], Finding]:
    return {(f.kind, f.value_key): f for f in findings}


def scrubbed(source: Path, target: Path, findings: list[Finding], aliases: MemoryAliases) -> str:
    apply(source, target, findings, CTX, aliases)
    return target.read_text(encoding="utf-8")


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


def test_scan_skips_addresses_in_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"10.1.2.3": "up", "ip": "10.1.2.4"}), encoding="utf-8")
    found = by_value(scan(path, CTX, MemoryAliases()).findings)
    assert ("ip4", "10.1.2.4") in found and ("ip4", "10.1.2.3") not in found


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


def test_reverse_restores_everything_but_secrets(source: Path, tmp_path: Path) -> None:
    aliases = MemoryAliases()
    findings = scan(source, CTX, aliases).findings
    _, counts = apply(source, tmp_path / "out.txt", findings, CTX, aliases)
    out = (tmp_path / "out.txt").read_text(encoding="utf-8")
    secrets_only = [f if f.kind == "secret" else dataclasses.replace(f, checked=False) for f in findings]
    expected = scrubbed(source, tmp_path / "secrets.txt", secrets_only, MemoryAliases())
    text, replaced = reverse(out, aliases.pairs())
    assert text == expected
    assert replaced == sum(counts.values()) - counts["secret"]
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
