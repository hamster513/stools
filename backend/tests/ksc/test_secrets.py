"""Скрытие секретов (аудит M4): новые маркеры, двоичные значения, параметры задач и повторное
скрытие при разборе файла — одно правило у онлайн-сборщика, разбора и PowerShell-скрипта."""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any

import pytest

from api.modules.ksc.core import client as client_mod
from api.modules.ksc.core.client import KscClient
from api.modules.ksc.core.collector import collect
from api.modules.ksc.core.export import load_export
from api.modules.ksc.core.secrets import BINARY_KEEP, HIDDEN, SECRET_MARKERS, hide_secrets
from tests.ksc.fake_ksc import PASSWORD, USER, FakeKsc, http_factory_for
from tests.ksc.synthetic import (
    BAIT_VALUES,
    add_secret_bait,
    assert_bait_hidden,
    build_export,
    expected_policy_contents,
)

SCRIPT = Path("api/modules/ksc/collector/STools-KSC-Collector.ps1")


def test_new_markers_hide_strings_and_keep_flags_and_numbers() -> None:
    value = {"Passphrase": "a", "ApiKey": "b", "API_KEY": "c", "AuthCode": "d", "PIN": "e", "EncryptionKey": "f",
             "Comment": "keep", "Enabled": True, "Timeout": 30, "PinEnabled": True}
    assert hide_secrets(value) == {"Passphrase": HIDDEN, "ApiKey": HIDDEN, "API_KEY": HIDDEN, "AuthCode": HIDDEN, "PIN": HIDDEN,
                                   "EncryptionKey": HIDDEN, "Comment": "keep", "Enabled": True, "Timeout": 30, "PinEnabled": True}


def test_binary_is_hidden_under_any_key_other_typed_values_stay() -> None:
    when = {"type": "datetime", "value": "2026-09-15T12:00:00Z"}
    value = {"Certificate": {"type": "binary", "value": "AAAA"}, "When": when, "N": {"type": "long", "value": 5},
             "Nested": {"type": "params", "value": {"Blob": {"type": "binary", "value": "BBBB"}, "Name": "x"}}}
    assert hide_secrets(value) == {"Certificate": HIDDEN, "When": when, "N": {"type": "long", "value": 5},
                                   "Nested": {"type": "params", "value": {"Blob": HIDDEN, "Name": "x"}}}
    assert hide_secrets({"type": "binary", "value": "AAAA"}) == HIDDEN


def test_address_octets_are_kept_longer_binary_under_octets_is_hidden() -> None:
    """Сборщик 1.3: адрес IPv4/IPv6 (4 или 16 байт) под ключом `octets` — не секрет; двоичное
    длиннее 16 байт под тем же ключом — не адрес, скрывается как прежде."""
    v4 = {"type": "binary", "value": "wKgBAQ=="}
    assert hide_secrets({"scope": {"remoteAddresses": [{"octets": v4, "mask": 32}]}}) == {"scope": {"remoteAddresses": [{"octets": v4, "mask": 32}]}}
    v6 = {"type": "binary", "value": base64.b64encode(bytes(range(16))).decode()}
    assert hide_secrets({"Octets": v6}) == {"Octets": v6}
    assert hide_secrets({"octets": {"type": "binary", "value": base64.b64encode(bytes(24)).decode()}}) == {"octets": HIDDEN}
    assert hide_secrets({"octets": {"type": "binary", "value": "не base64"}}) == {"octets": HIDDEN}
    assert hide_secrets({"address": v4}) == {"address": HIDDEN}
    assert BINARY_KEEP == ("octets",)


def test_empty_string_under_marker_stays_empty() -> None:
    """Сборщик 1.3: под признаком скрывается только непустая строка — «не настроено» отличимо от
    «настроено»."""
    assert hide_secrets({"passwordProtection": {"login": "", "passwordHash": "abc"}}) == {"passwordProtection": {"login": "", "passwordHash": HIDDEN}}
    assert hide_secrets({"Login": "", "Name": "x"}, "KLPRSS_Password") == {"Login": "", "Name": HIDDEN}
    value = {"scope": {"remoteAddresses": [{"octets": {"type": "binary", "value": "wKgBAQ=="}}]}, "passwordProtection": {"login": "", "hash": "abc"}}
    assert hide_secrets(hide_secrets(value)) == hide_secrets(value)


def test_section_name_with_marker_hides_whole_section() -> None:
    assert hide_secrets({"X": "v", "Y": 1}, "KLPRSS_ApiKeys") == {"X": HIDDEN, "Y": 1}
    assert hide_secrets({"X": "v"}, "KLPRSS_Basic") == {"X": "v"}


def test_hiding_is_idempotent() -> None:
    once = expected_policy_contents()
    assert {pid: {**p, "sections": {n: hide_secrets(v, n) for n, v in p["sections"].items()}} for pid, p in once.items()} == once


@pytest.mark.parametrize("variant", ["", "params"])
def test_online_collector_hides_new_markers_binary_and_task_params(monkeypatch: Any, variant: str) -> None:
    fake = FakeKsc(data=add_secret_bait(build_export()), variant=variant)
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(fake))
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, username=USER)
    text = json.dumps(raw, ensure_ascii=False)
    assert not [v for v in BAIT_VALUES if v in text]  # уже в собранном, до разбора
    assert_bait_hidden(load_export(json.dumps(raw).encode()))


def test_load_export_hides_secrets_of_old_or_hand_edited_file() -> None:
    """Файл, собранный старым сборщиком или поправленный руками: содержимое политик и параметры
    задач как пришли от KSC, без скрытия. Разбор скрывает их сам."""
    raw = add_secret_bait(build_export())
    export = load_export(json.dumps(raw).encode())
    assert_bait_hidden(export)
    assert export.policy_contents["3"] == expected_policy_contents()["3"]


def test_load_export_keeps_already_hidden_file_as_is() -> None:
    raw = build_export()
    raw["policy_contents"] = expected_policy_contents()
    export = load_export(json.dumps(raw).encode())
    assert export.policy_contents == expected_policy_contents()
    assert [t["TASK_INFO_PARAMS"] for t in export.tasks] == [t["TASK_INFO_PARAMS"] for t in build_export()["tasks"]]


def test_script_mirrors_secret_markers_and_binary_rule() -> None:
    text = SCRIPT.read_text(encoding="utf-8-sig")
    m = re.search(r"^\$SecretMarkers = @\(([^)]*)\)", text, re.MULTILINE)
    assert m is not None
    assert tuple(re.findall(r'"([^"]+)"', m.group(1))) == SECRET_MARKERS
    keep = re.search(r"^\$BinaryKeep = @\(([^)]*)\)", text, re.MULTILINE)
    assert keep is not None and tuple(re.findall(r'"([^"]+)"', keep.group(1))) == BINARY_KEEP
    assert '"TASK_ADDITIONAL_PARAMS", "TASK_INFO_PARAMS"' in text
